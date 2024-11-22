package burp.ui;

import burp.*;
import burp.bean.APIRecordBean;
import burp.bean.ZacConfigBean;
import burp.dao.APIRecordDao;
import burp.ui.UIHepler.GridBagConstraintsHelper;
import burp.utils.JsonProcessorUtil;
import burp.utils.UrlCacheUtil;
import burp.utils.Utils;
import cn.hutool.poi.excel.ExcelUtil;
import cn.hutool.poi.excel.ExcelWriter;
import lombok.Data;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static burp.IParameter.*;
import static burp.dao.ZacConfigDao.*;

public class APICollectUI implements UIHandler, IMessageEditorController, IHttpListener {
    private static final List<UrlEntry> urldata = new ArrayList<>();  // urldata
    private static final List<PayloadEntry> payloaddata = new ArrayList<>(); // payload
    private static final List<PayloadEntry> payloaddata2 = new ArrayList<>(); // payload
    private static final Set<String> urlHashList = new HashSet<>(); // 存放url的hash值
    private static final List<String> listErrorKey = new ArrayList<>(); // // 存放错误key
    private static final ConcurrentHashMap<Integer, StringBuilder> vul = new ConcurrentHashMap<>();// 防止插入重复
    private static JTable urltable; // url 表格
    private static JTable payloadtable; // payload 表格
    private static boolean isPassiveScan; // 是否被动扫描
    private static boolean isWhiteDomain; // 是否白名单域名

    private static boolean isCollectResponse; // 是否收集响应体

    private static boolean isCollectUnique; // 是否去重
    private static List<ZacConfigBean> zac_configPayload = new ArrayList<>(); // 存放sql关键字
    private static List<String> domainList = new ArrayList<>(); // 存放域名白名单
    private static List<ZacConfigBean> headerList = new ArrayList<>(); // 存放header白名单

    public AbstractTableModel model = new PayloadModel(); // payload 模型
    private IHttpRequestResponse currentlyDisplayedItem; // 请求响应
    private JPanel panel; // 主面板
    private JTabbedPane tabbedPanereq; // 左下的请求
    private JTabbedPane tabbedPaneresp; // 左下的响应
    private JScrollPane urltablescrollpane; // url 表格滚动
    private JScrollPane payloadtablescrollpane; // payload 表格滚动
    private JCheckBox passiveScanCheckBox; // 被动扫描选择框
    private JCheckBox checkWhiteListCheckBox; // 白名单域名检测选择框
    private JCheckBox collectResponseCheckBox; // 是否对参数进行url编码
    private JButton saveWhiteListButton; // 白名单域名保存按钮
    private JButton saveHeaderListButton; // 保存header按钮
    private JTextArea whiteListTextArea; // 白名单域名输入框列表
    private JTextArea headerTextArea; // header检测数据框列表
    private JButton refreshTableButton; // 刷新表格按钮
    private JButton clearTableButton; // 清空表格按钮
    private IMessageEditor HRequestTextEditor; // 请求
    private IMessageEditor HResponseTextEditor; // 响应

    // API收集核心方法
    public static void Collect(IHttpRequestResponse[] requestResponses, boolean isSend) {
        // 常规初始化流程代码
        IHttpRequestResponse baseRequestResponse = requestResponses[0]; // 获取第一个请求
        IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse); // 获取请求
        List<String> reqheaders = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders(); // 获取请求头
        String host = baseRequestResponse.getHttpService().getHost(); // 获取域名
        String method = analyzeRequest.getMethod(); // 获取请求方法
        URL rdurlURL = analyzeRequest.getUrl(); // 获取请求url
        String url = analyzeRequest.getUrl().toString(); // 获取请求url
        List<IParameter> paraLists = analyzeRequest.getParameters(); // 获取参数列表

        // 如果method不是get或者post方式直接返回
        if (!method.equals("GET") && !method.equals("POST")) {
            return;
        }

        // url 中匹配为静态资源
        if (Utils.isUrlBlackListSuffix(url)) {
            return;
        }

        // 判断参数类型，不符合的直接跳过检测
        boolean ruleHit = true; // 默认设置为true，表示命中规则
        for (IParameter para : paraLists) {
            if ((para.getType() == PARAM_URL || para.getType() == PARAM_BODY || para.getType() == PARAM_JSON)
            ) {
                ruleHit = false; // 如果有 URL、BODY、JSON 参数或者开启了 cookie 或 header 检测，则不命中规则
                break;
            }
        }

        if (ruleHit) {
            return; // 如果命中规则，则直接返回
        }

        // 如果不是手动发送的请求，检测url是否重复及域名是否匹配
        if (!isSend) {
            if (!UrlCacheUtil.checkUrlUnique("zac_config", method, rdurlURL, paraLists)) {
                return;
            }
            if (isWhiteDomain) {
                // 如果未匹配到 直接返回
                if (!Utils.isMatchDomainName(host, domainList)) {
                    return;
                }
            }
        }

        // 将原始流量数据包发送一次,用来做后面的对比
        byte[] request = baseRequestResponse.getRequest();
        int bodyOffset = analyzeRequest.getBodyOffset();
        byte[] body = Arrays.copyOfRange(request, bodyOffset, request.length);
        byte[] postMessage = Utils.helpers.buildHttpMessage(reqheaders, body);
        IHttpRequestResponse originalRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), postMessage);
        byte[] responseBody = originalRequestResponse.getResponse();

        // 如果有返回,尝试拿到Content-Length
        int originalLength = 0;
        if (responseBody != null) {
            IResponseInfo originalReqResponse = Utils.helpers.analyzeResponse(responseBody);
            List<String> sqlHeaders = originalReqResponse.getHeaders();
            String contentLength = HelperPlus.getHeaderValueOf(sqlHeaders, "Content-Length");
            if (contentLength != null) {
                originalLength = Integer.parseInt(contentLength);
            } else {
                originalLength = Integer.parseInt(String.valueOf(responseBody.length));
            }
        }

        // 如果原始包没有返回数据,则return
        if (originalLength == 0) {
            return;
        }

        // 尝试添加一个url到url表格
        int logid = addUrl(method, url, originalLength, baseRequestResponse);
        addToVulStr(logid, "收集完成");
        // 检测常规注入
        for (IParameter para : paraLists) {
            // 如果参数符合下面的类型，则进行检测
            if (para.getType() == PARAM_URL || para.getType() == PARAM_BODY || para.getType() == PARAM_JSON) {
                String paraName = para.getName();
                String paraValue = para.getValue();
                // 检测常规参数的注入
                if (para.getType() == PARAM_URL || para.getType() == PARAM_BODY) {
                    if (paraName.isEmpty()) {
                        break;
                    }

                    // 记录payload测试结果
                    addPayload(
                            logid,
                            "Url",
                            paraName,
                            paraValue,
                            Utils.getCurrentTime(),
                            null
                    );
                }

                // 检测json类型的注入
                if (para.getType() == PARAM_JSON) {
                    // 获取JSON请求体
                    String request_data = Utils.helpers.bytesToString(baseRequestResponse.getRequest()).split("\r\n\r\n")[1];
                    if (request_data.isEmpty()) {
                        break;
                    }

                    // 记录payload测试结果
                    addPayload(
                            logid,
                            "JSON",
                            paraName,
                            paraValue,
                            Utils.getCurrentTime(),
                            null
                    );

                }

            }
        }

        // 更新数据
        updateUrl(logid, method, url, originalLength, vul.get(logid).toString(), originalRequestResponse);
    }

    // 在json结果列表中查找指定路径的结果
    private static JsonProcessorUtil.ProcessResult findResultByPath(List<JsonProcessorUtil.ProcessResult> results, String path) {
        return results.stream()
                .filter(r -> r.getParamPath().equals(path))
                .findFirst()
                .orElse(null);
    }

    // 更新url数据到表格
    public static void updateUrl(int index, String method, String url, int length, String message, IHttpRequestResponse requestResponse) {
        synchronized (urldata) {
            if (index >= 0 && index < urldata.size()) {
                urldata.set(index, new UrlEntry(index, method, url, length, message, requestResponse));
            }
            urltable.updateUI();
            payloadtable.updateUI();
        }
    }

    // 获取响应包的响应体内容
    private static String getResponseBody(IHttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.getResponse() == null) {
            return "";
        }
        byte[] response = requestResponse.getResponse();
        IResponseInfo responseInfo = Utils.helpers.analyzeResponse(response);
        int bodyOffset = responseInfo.getBodyOffset();

        return new String(Arrays.copyOfRange(response, bodyOffset, response.length));
    }

    // 获取请求包的响应体内容
    private static String getRequestBody(IHttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.getRequest() == null) {
            return "";
        }
        byte[] response = requestResponse.getRequest();
        IResponseInfo responseInfo = Utils.helpers.analyzeResponse(response);
        int bodyOffset = responseInfo.getBodyOffset();

        return new String(Arrays.copyOfRange(response, bodyOffset, response.length));
    }

    // 添加url数据到表格
    public static int addUrl(String method, String url, int length, IHttpRequestResponse requestResponse) {
        synchronized (urldata) {
            int id = urldata.size();
            urldata.add(new UrlEntry(id, method, url, length, "正在检测", requestResponse));
            APIRecordDao.saveAPIRecord(new APIRecordBean(method, url, getRequestBody(requestResponse), getResponseBody(requestResponse)));
            urltable.updateUI();
            payloadtable.updateUI();
            return id;
        }
    }

    // 添加漏洞数据到表格
    public static void addToVulStr(int key, CharSequence value) {
        // 检查是否已经存在该键，如果不存在则创建一个新的 ArrayList 存储值
        vul.computeIfAbsent(key, k -> new StringBuilder()).append(value).append(", ");
    }

    // 添加payload数据到表格
    public static void addPayload(int selectId, String type, String key, String value, String time, IHttpRequestResponse requestResponse) {
        synchronized (payloaddata2) {
            payloaddata2.add(new PayloadEntry(selectId, type, key, value, time, requestResponse));
            urltable.updateUI();
            payloadtable.updateUI();
        }
    }


    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse iHttpRequestResponse) {
        if (isPassiveScan && toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && !messageIsRequest) {
            synchronized (urldata) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        Collect(new IHttpRequestResponse[]{iHttpRequestResponse}, false);
                    }
                });
                thread.start();
            }
        }
    }

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public void init() {
        // 获取所有报错关键字
        List<ZacConfigBean> sqlErrorKey = getSqlListsByType("sqlErrorKey");
        for (ZacConfigBean zacConfigBean : sqlErrorKey) {
            listErrorKey.add(zacConfigBean.getValue());
        }

        // 获取所有payload
        zac_configPayload = getSqlListsByType("payload");

        List<ZacConfigBean> domain = getSqlListsByType("domain");
        // 将domain转为List<String>
        domainList = new ArrayList<>();
        for (ZacConfigBean zacConfigBean : domain) {
            domainList.add(zacConfigBean.getValue());
        }

        // 获取数据库中的header
        headerList = getSqlListsByType("header");

        setupUI();
        setupData();
    }

    private void setupData() {

        refreshTableButton.addActionListener(e -> {
            urltable.updateUI();
            payloadtable.updateUI();
        });
        clearTableButton.addActionListener(e -> {
            urldata.clear();
            payloaddata.clear();
            payloaddata2.clear();
            HRequestTextEditor.setMessage(new byte[0], true);
            HResponseTextEditor.setMessage(new byte[0], false);
            urlHashList.clear();
            urltable.updateUI();
            payloadtable.updateUI();
        });

        // 保存header
        saveHeaderListButton.addActionListener(e -> {
            if (urldata.isEmpty()) {
                JOptionPane.showMessageDialog(null, "暂无数据", "提示", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            // 创建ExcelWriter，指定文件路径和分隔符，这里使用逗号分隔符导出Xlsx格式
            ExcelWriter writer = ExcelUtil.getWriter("D:\\Z0fData\\API接口" + System.currentTimeMillis() + ".xlsx", "API测试结果集合");
            // 添加标题，根据需要添加别名
            writer.addHeaderAlias("column0", "序号");
            writer.addHeaderAlias("column1", "请求方式");
            writer.addHeaderAlias("column2", "URL");
            writer.addHeaderAlias("column3", "请求体");
            writer.addHeaderAlias("column4", "响应体");
            List<Map<String, Object>> data = new ArrayList<>();
            for (int i = 0; i < urldata.size(); i++) {
                Map<String, Object> row1 = new HashMap<>();
                row1.put("column0", urldata.get(i).getId());
                row1.put("column1", urldata.get(i).getMethod());
                row1.put("column2", urldata.get(i).getUrl());
                String highRequest = new String(urldata.get(i).getRequestResponse().getRequest(), StandardCharsets.UTF_8);
                if (highRequest.length() > 32767) {
                    highRequest = highRequest.substring(0, 32767);
                }
                row1.put("column3", highRequest);
                String highResponse = new String(urldata.get(i).getRequestResponse().getResponse(), StandardCharsets.UTF_8);
                if (highResponse.length() > 32767) {
                    highResponse = highResponse.substring(0, 32767);
                }
                row1.put("column4", highResponse);
                data.add(row1);
            }
            // 写入数据到CSV文件
            writer.write(data, true);
            writer.close();
            JOptionPane.showMessageDialog(null, "保存成功，请到D:\\Z0fData\\查看", "提示", JOptionPane.INFORMATION_MESSAGE);
        });

        // 保存白名单域名
        saveWhiteListButton.addActionListener(e -> {
            String whiteListTextAreaText = whiteListTextArea.getText();
            deleteSqlByType("domain");
            // 如果包含换行符，就分割成多个domain
            if (whiteListTextAreaText.contains("\n")) {
                String[] whitedomains = whiteListTextAreaText.split("\n");
                for (String whitedomain : whitedomains) {
                    if (whitedomain.isEmpty()) {
                        continue;
                    }
                    ZacConfigBean zacConfigBean = new ZacConfigBean("domain", whitedomain);
                    saveSql(zacConfigBean);
                }
            } else {
                if (whiteListTextAreaText.isEmpty()) {
                    return;
                }
                ZacConfigBean zacConfigBean = new ZacConfigBean("domain", whiteListTextAreaText);
                saveSql(zacConfigBean);
            }
            List<ZacConfigBean> domain = getSqlListsByType("domain");
            // 将domain转为List<String>
            for (ZacConfigBean zacConfigBean : domain) {
                domainList.add(zacConfigBean.getValue());
            }
            whiteListTextArea.updateUI();
            JOptionPane.showMessageDialog(null, "保存成功", "提示", JOptionPane.INFORMATION_MESSAGE);
        });

        // 被动扫描选择框事件
        passiveScanCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                isPassiveScan = passiveScanCheckBox.isSelected();
            }
        });

        // 白名单域名检测选择框事件
        checkWhiteListCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                isWhiteDomain = checkWhiteListCheckBox.isSelected();
            }
        });

        // 白名单域名检测选择框事件
        collectResponseCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                isCollectResponse = collectResponseCheckBox.isSelected();
            }
        });


        // 数据库获取header,输出到面板
        List<ZacConfigBean> header = getSqlListsByType("header");
        for (ZacConfigBean zacConfigBean : header) {
            // 如果是最后一个，就不加换行符
            if (header.indexOf(zacConfigBean) == header.size() - 1) {
                headerTextArea.setText(headerTextArea.getText() + zacConfigBean.getValue());
                break;
            }
            headerTextArea.setText(headerTextArea.getText() + zacConfigBean.getValue() + "\n");
        }

        // 数据库获取白名单域名,输出到面板
        List<ZacConfigBean> domains = getSqlListsByType("domain");
        for (ZacConfigBean zacConfigBean : domains) {
            // 如果是最后一个，就不加换行符
            if (domains.indexOf(zacConfigBean) == domains.size() - 1) {
                whiteListTextArea.setText(whiteListTextArea.getText() + zacConfigBean.getValue());
                break;
            }
            whiteListTextArea.setText(whiteListTextArea.getText() + zacConfigBean.getValue() + "\n");
        }

    }

    private void setupUI() {
        // 注册被动扫描监听器
        Utils.callbacks.registerHttpListener(this);
        panel = new JPanel();
        panel.setLayout(new BorderLayout());

        // 左边的面板
        // 左边的上下分割 上部分和下部分占比6:4
        JSplitPane leftSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        leftSplitPane.setResizeWeight(0.6);
        leftSplitPane.setDividerLocation(0.6);

        // 左边的上部分左右对称分割
        JSplitPane zsSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        zsSplitPane.setResizeWeight(0.5);
        zsSplitPane.setDividerLocation(0.5);
        // 添加到leftSplitPane
        // 左右对称分割面板

        // 添加到zsSplitPane
        urltablescrollpane = new JScrollPane();
        zsSplitPane.setLeftComponent(urltablescrollpane);
        UrlModel urlModel = new UrlModel();
        urltable = new URLTable(urlModel);
        urltablescrollpane.setViewportView(urltable);


        // 创建一个自定义的单元格渲染器
        DefaultTableCellRenderer renderer = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                JLabel label = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                label.setHorizontalAlignment(JLabel.CENTER);
                label.setHorizontalTextPosition(JLabel.CENTER);
                label.setIconTextGap(0);
                label.setMaximumSize(new Dimension(Integer.MAX_VALUE, label.getPreferredSize().height));
                label.setToolTipText((String) value); // 设置鼠标悬停时显示的提示文本
                return label;
            }
        };

        // 表格渲染
        urltable.getColumnModel().getColumn(4).setCellRenderer(renderer);


        payloadtablescrollpane = new JScrollPane();
        zsSplitPane.setRightComponent(payloadtablescrollpane);
        PayloadModel payloadModel = new PayloadModel();
        payloadtable = new PayloadTable(payloadModel);
        payloadtablescrollpane.setViewportView(payloadtable);

        // 表格渲染
        payloadtable.getColumnModel().getColumn(0).setCellRenderer(renderer);

        // 左边的下部分左右对称分割
        JSplitPane zxSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        zxSplitPane.setResizeWeight(0.5);
        zxSplitPane.setDividerLocation(0.5);
        // 添加到leftSplitPane下面
        HRequestTextEditor = Utils.callbacks.createMessageEditor(APICollectUI.this, true);
        HResponseTextEditor = Utils.callbacks.createMessageEditor(APICollectUI.this, false);
        tabbedPanereq = new JTabbedPane();
        tabbedPanereq.addTab("Request", HRequestTextEditor.getComponent());
        tabbedPaneresp = new JTabbedPane();
        tabbedPaneresp.addTab("Response", HResponseTextEditor.getComponent());
        zxSplitPane.setLeftComponent(tabbedPanereq);
        zxSplitPane.setRightComponent(tabbedPaneresp);

        leftSplitPane.setLeftComponent(zsSplitPane);
        leftSplitPane.setRightComponent(zxSplitPane);


        // 右边的上下按7:3分割
        JSplitPane rightSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        rightSplitPane.setResizeWeight(0.7);
        rightSplitPane.setDividerLocation(0.7);


        // 右边的上部分
        // 添加被动扫描选择框
        passiveScanCheckBox = new JCheckBox("被动扫描");
        // 添加白名单域名检测选择框
        checkWhiteListCheckBox = new JCheckBox("白名单域名检测");
        // 收集响应包数据选择框
        collectResponseCheckBox = new JCheckBox("收集响应包数据");
        // 白名单域名保存按钮
        saveWhiteListButton = new JButton("保存白名单域名");
        // 保存header按钮
        saveHeaderListButton = new JButton("导出Xlsx");
        // 白名单域名输入框列表
        whiteListTextArea = new JTextArea(5, 10);
        whiteListTextArea.setLineWrap(false); // 自动换行
        whiteListTextArea.setWrapStyleWord(false); // 按单词换行
        JScrollPane whiteListTextAreascrollPane = new JScrollPane(whiteListTextArea);

        // header检测数据框列表
        headerTextArea = new JTextArea(5, 10);
        headerTextArea.setLineWrap(true); // 自动换行
        headerTextArea.setWrapStyleWord(true); // 按单词换行
        JScrollPane headerTextAreascrollPane = new JScrollPane(headerTextArea);
        // 刷新表格按钮
        refreshTableButton = new JButton("刷新表格");
        // 清空表格按钮
        clearTableButton = new JButton("清空表格");
        // 白名单域名label
        JLabel whiteDomainListLabel = new JLabel("白名单域名");
        // 检测header label
        JLabel headerLabel = new JLabel("header检测列表");

        // 添加到右边的上部分
        JPanel rightTopPanel = new JPanel();
        rightTopPanel.setLayout(new GridBagLayout());
        rightTopPanel.add(passiveScanCheckBox, new GridBagConstraintsHelper(0, 0, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(checkWhiteListCheckBox, new GridBagConstraintsHelper(0, 1, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(collectResponseCheckBox, new GridBagConstraintsHelper(2, 1, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(saveWhiteListButton, new GridBagConstraintsHelper(0, 2, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(saveHeaderListButton, new GridBagConstraintsHelper(1, 2, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(whiteDomainListLabel, new GridBagConstraintsHelper(0, 3, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(whiteListTextAreascrollPane, new GridBagConstraintsHelper(0, 4, 3, 1).setInsets(5).setIpad(0, 0).setWeight(1.0, 1.0).setAnchor(GridBagConstraints.CENTER).setFill(GridBagConstraints.BOTH));
        rightTopPanel.add(headerLabel, new GridBagConstraintsHelper(0, 5, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(headerTextAreascrollPane, new GridBagConstraintsHelper(0, 6, 3, 1).setInsets(5).setIpad(0, 0).setWeight(1.0, 1.0).setAnchor(GridBagConstraints.CENTER).setFill(GridBagConstraints.BOTH));
        rightTopPanel.add(refreshTableButton, new GridBagConstraintsHelper(0, 7, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(clearTableButton, new GridBagConstraintsHelper(1, 7, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));

        rightSplitPane.setTopComponent(rightTopPanel);

        // 左右分割面板添加rightDownLeftPanel和rightDownRightPanel
        JSplitPane rightDownPanel = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        rightDownPanel.setResizeWeight(0.5);
        rightDownPanel.setDividerLocation(0.5);

        rightSplitPane.setBottomComponent(rightDownPanel);
        panel.add(leftSplitPane, BorderLayout.CENTER);
        panel.add(rightSplitPane, BorderLayout.EAST);

    }

    @Override
    public JPanel getPanel(IBurpExtenderCallbacks callbacks) {
        return panel;
    }

    @Override
    public String getTabName() {
        return "API收集";
    }

    // url 实体类
    @Data
    public static class UrlEntry {
        final int id;
        final String method;
        final String url;
        final int length;
        final String status;
        final IHttpRequestResponse requestResponse;

        UrlEntry(int id, String method, String url, int length, String status, IHttpRequestResponse requestResponse) {
            this.id = id;
            this.method = method;
            this.url = url;
            this.length = length;
            this.status = status;
            this.requestResponse = requestResponse;
        }

    }

    // payload 实体类
    public static class PayloadEntry {
        final int selectId;
        final String type;
        final String key;
        final String value;

        final String time;
        final IHttpRequestResponse requestResponse;

        PayloadEntry(int selectId, String type, String key, String value, String time, IHttpRequestResponse requestResponse) {
            this.selectId = selectId;
            this.type = type;
            this.key = key;
            this.value = value;
            this.time = time;
            this.requestResponse = requestResponse;
        }
    }

    // url 模型
    static class UrlModel extends AbstractTableModel {

        @Override
        public int getRowCount() {
            return urldata.size();
        }

        @Override
        public int getColumnCount() {
            return 5;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            switch (columnIndex) {
                case 0:
                    return urldata.get(rowIndex).id;
                case 1:
                    return urldata.get(rowIndex).method;
                case 2:
                    return urldata.get(rowIndex).url;
                case 3:
                    return urldata.get(rowIndex).length;
                case 4:
                    return urldata.get(rowIndex).status;
                default:
                    return null;
            }
        }

        @Override
        public String getColumnName(int column) {
            switch (column) {
                case 0:
                    return "id";
                case 1:
                    return "Method";
                case 2:
                    return "Url";
                case 3:
                    return "Length";
                case 4:
                    return "Status";
                default:
                    return null;
            }
        }
    }

    // Payload 模型
    static class PayloadModel extends AbstractTableModel {

        @Override
        public int getRowCount() {
            return payloaddata.size();
        }

        @Override
        public int getColumnCount() {
            return 4;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            switch (columnIndex) {
                case 0:
                    return payloaddata.get(rowIndex).type;
                case 1:
                    return payloaddata.get(rowIndex).key;
                case 2:
                    return payloaddata.get(rowIndex).value;
                case 3:
                    return payloaddata.get(rowIndex).time;
                default:
                    return null;
            }
        }

        @Override
        public String getColumnName(int column) {
            switch (column) {
                case 0:
                    return "类型";
                case 1:
                    return "参数";
                case 2:
                    return "参数值";
                case 3:
                    return "时间";
                default:
                    return null;
            }
        }
    }

    // url 表格
    private class URLTable extends JTable {
        public URLTable(AbstractTableModel model) {
            super(model);
            TableColumnModel columnModel = getColumnModel();
            columnModel.getColumn(0).setMaxWidth(50);
            columnModel.getColumn(1).setMaxWidth(100);
        }

        @Override
        public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
            UrlEntry logEntry = urldata.get(rowIndex);
            int select_id = logEntry.id;
            payloaddata.clear();
            for (PayloadEntry payloadEntry : payloaddata2) {
                if (payloadEntry.selectId == select_id) {
                    payloaddata.add(payloadEntry);
                }
            }
            payloadtable.updateUI();

            model.fireTableRowsInserted(payloaddata.size(), payloaddata.size());
            model.fireTableDataChanged();
            HRequestTextEditor.setMessage(logEntry.requestResponse.getRequest(), true);
            if (logEntry.requestResponse.getResponse() == null) {
                HResponseTextEditor.setMessage(new byte[0], false);
            } else {
                HResponseTextEditor.setMessage(logEntry.requestResponse.getResponse(), false);
            }
            currentlyDisplayedItem = logEntry.requestResponse;
            super.changeSelection(rowIndex, columnIndex, toggle, extend);
        }
    }

    // payload 表格
    private class PayloadTable extends JTable {
        public PayloadTable(AbstractTableModel model) {
            super(model);
            TableColumnModel columnModel = getColumnModel();
            columnModel.getColumn(0).setMaxWidth(50);
//            columnModel.getColumn(6).setMaxWidth(50);
        }

        @Override
        public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {

            PayloadEntry dataEntry = payloaddata.get(rowIndex);
            HRequestTextEditor.setMessage(dataEntry.requestResponse.getRequest(), true);
            if (dataEntry.requestResponse.getResponse() == null) {
                HResponseTextEditor.setMessage(new byte[0], false);
            } else {
                HResponseTextEditor.setMessage(dataEntry.requestResponse.getResponse(), false);
            }
            currentlyDisplayedItem = dataEntry.requestResponse;
            super.changeSelection(rowIndex, columnIndex, toggle, extend);
        }
    }

}