package burp.ui;

import burp.*;
import burp.bean.APIRecordBean;
import burp.bean.ZacConfigBean;
import burp.dao.APIRecordDao;
import burp.ui.UIHepler.GridBagConstraintsHelper;
import burp.utils.JsonProcessorUtil;
import burp.utils.UrlCacheUtil;
import burp.utils.Utils;
import cn.hutool.poi.excel.ExcelReader;
import cn.hutool.poi.excel.ExcelUtil;
import cn.hutool.poi.excel.ExcelWriter;
import lombok.Data;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.File;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static burp.IParameter.*;
import static burp.dao.ZacConfigDao.*;

public class APICollectUI extends Component implements UIHandler, IMessageEditorController, IHttpListener {
    private static final List<UrlEntry> urldata = new ArrayList<>();  // urldata
    private static final List<PayloadEntry> payloaddata = new ArrayList<>(); // payload
    private static final List<PayloadEntry> payloaddata2 = new ArrayList<>(); // payload
    private static final Set<String> urlHashList = new HashSet<>(); // 存放url的hash值
    private static final ConcurrentHashMap<Integer, StringBuilder> vul = new ConcurrentHashMap<>();// 防止插入重复
    private static JTable urltable; // url 表格
    private static JTable payloadtable; // payload 表格
    private static boolean isPassiveScan; // 是否被动扫描
    private static boolean isWhiteDomain; // 是否白名单域名
    private static boolean isCollectResponse; // 是否收集响应体
    private static boolean isCollectUnique; // 是否去重
    private static List<String> domainList = new ArrayList<>(); // 存放域名白名单
    private static JCheckBox collectGETCheckBox; // GET收集
    private static JCheckBox collectPOSTCheckBox; // POST收集
    private static JCheckBox collectDELETECheckBox; // DELETE收集
    private static JCheckBox collectPUTCheckBox; // PUT收集
    private static JCheckBox collectHEADCheckBox; // HEAD收集
    private static JCheckBox collectOPTIONSCheckBox; // OPTIONS收集
    private static JCheckBox collectCONNECTCheckBox; // CONNECT收集
    private static JCheckBox collectTRACECheckBox; // TRACE收集
    public AbstractTableModel model = new PayloadModel(); // payload 模型
    private IHttpRequestResponse currentlyDisplayedItem; // 请求响应
    private JPanel panel; // 主面板
    private JTabbedPane tabbedPanereq; // 左下的请求
    private JTabbedPane tabbedPaneresp; // 左下的响应
    private JScrollPane urltablescrollpane; // url 表格滚动
    private JScrollPane payloadtablescrollpane; // payload 表格滚动
    private JCheckBox passiveScanCheckBox; // 被动扫描选择框
    private JCheckBox checkWhiteListCheckBox; // 白名单域名检测选择框
    private JCheckBox collectResponseCheckBox; // 是否对响应包进行收集
    private JCheckBox comparerToolCheckBox;
    private JCheckBox decoderToolCheckBox;
    private JCheckBox extenderToolCheckBox;
    private JCheckBox intruderToolCheckBox;
    private JCheckBox proxyToolCheckBox;
    private JCheckBox repeaterToolCheckBox;
    private JCheckBox scannerToolCheckBox;
    private JCheckBox sequencerToolCheckBox;
    private JCheckBox spiderToolCheckBox;
    private JCheckBox suiteToolCheckBox;
    private JCheckBox targetToolCheckBox;
    private JButton saveWhiteListButton; // 白名单域名保存按钮
    private JButton saveAPIDataButton; // 导出API接口数据按钮
    private JButton importAPIDataButton; // 导入API接口数据按钮
    private JTextArea whiteListTextArea; // 白名单域名输入框列表
    private JButton refreshTableButton; // 刷新表格按钮
    private JButton clearTableButton; // 清空表格按钮
    private JButton saveListenerConfigButton;
    private IMessageEditor HRequestTextEditor; // 请求
    private IMessageEditor HResponseTextEditor; // 响应

    private SwingWorker<List<Object[]>, Void> importActionWorker;


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
        String path = analyzeRequest.getUrl().getPath();

        List<IParameter> paraLists = analyzeRequest.getParameters(); // 获取参数列表

        // 如果method不是勾选的指定的方法直接返回
        if (!validMethodEnabled(method)) {
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
            String contentLength = Utils.getHeaderValueOf(sqlHeaders, "Content-Length");
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
        int logid = addUrl(method, host, path, url, originalLength, 0, baseRequestResponse);
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
        updateUrl(logid, method, host, path, url, originalLength, 1, vul.get(logid).toString(), originalRequestResponse);
    }

    // 在json结果列表中查找指定路径的结果
    private static JsonProcessorUtil.ProcessResult findResultByPath(List<JsonProcessorUtil.ProcessResult> results, String path) {
        return results.stream()
                .filter(r -> r.getParamPath().equals(path))
                .findFirst()
                .orElse(null);
    }

    // 更新url数据到表格
    public static void updateUrl(int index, String method, String host, String path, String url, int length, int counts, String message, IHttpRequestResponse requestResponse) {
        synchronized (urldata) {
            if (index >= 0 && index < urldata.size()) {
                urldata.set(index, new UrlEntry(index, method, host, path, url, length, counts, message, requestResponse));
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
    public static int addUrl(String method, String host, String path, String url, int length, int counts, IHttpRequestResponse requestResponse) {
        synchronized (urldata) {
            int id = urldata.size();
            urldata.add(new UrlEntry(id, method, host, path, url, length, counts, "正在检测", requestResponse));
            APIRecordDao.saveAPIRecord(new APIRecordBean(method, host, path, url, getRequestBody(requestResponse), getResponseBody(requestResponse)));
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

    /**
     * 校验是否勾选指定的方法
     *
     * @param method 方法的名称
     * @return true:已勾选 false:未勾选
     */
    public static boolean validMethodEnabled(String method) {
        switch (method) {
            case "POST":
                return collectPOSTCheckBox.isSelected();
            case "GET":
                return collectGETCheckBox.isSelected();
            case "PUT":
                return collectPUTCheckBox.isSelected();
            case "DELETE":
                return collectDELETECheckBox.isSelected();
            case "HEAD":
                return collectHEADCheckBox.isSelected();
            case "OPTIONS":
                return collectOPTIONSCheckBox.isSelected();
            case "TRACE":
                return collectTRACECheckBox.isSelected();
            case "CONNECT":
                return collectCONNECTCheckBox.isSelected();
        }
        return false;
    }

    private List<String> findFilesWithExtension(File directory, String extension) {
        List<String> filePaths = new ArrayList<>();
        if (directory.isDirectory()) {
            File[] files = directory.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (file.isDirectory()) {
                        filePaths.addAll(findFilesWithExtension(file, extension));
                    } else if (file.isFile() && file.getName().toLowerCase().endsWith(extension)) {
                        filePaths.add(file.getAbsolutePath());
                    }
                }
            }
        } else {
            filePaths.add(directory.getAbsolutePath());
        }
        return filePaths;
    }

    private String selectDirectory(boolean forDirectories) {
        JFileChooser chooser = new JFileChooser();
        chooser.setCurrentDirectory(new java.io.File(Utils.WORKDIR));
        chooser.setDialogTitle(String.format("Select a Directory%s", forDirectories ? "" : " or File"));
        FileNameExtensionFilter filter = new FileNameExtensionFilter(".xlsx Files", "xlsx");
        chooser.addChoosableFileFilter(filter);
        chooser.setFileFilter(filter);

        chooser.setFileSelectionMode(forDirectories ? JFileChooser.DIRECTORIES_ONLY : JFileChooser.FILES_AND_DIRECTORIES);
        chooser.setAcceptAllFileFilterUsed(!forDirectories);

        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File selectedDirectory = chooser.getSelectedFile();
            return selectedDirectory.getAbsolutePath();
        }

        return "";
    }

    private void importActionPerformed(ActionEvent e) {
        String exportDir = selectDirectory(false);
        if (exportDir.isEmpty()) {
            return;
        }

        if (importActionWorker != null && !importActionWorker.isDone()) {
            importActionWorker.cancel(true);
        }

        importActionWorker = new SwingWorker<List<Object[]>, Void>() {
            @Override
            protected List<Object[]> doInBackground() {
                List<String> filesWithExtension = findFilesWithExtension(new File(exportDir), ".xlsx");
                // 指定Excel文件路径
                File file = new File(filesWithExtension.get(0));
                // 创建ExcelReader对象，这里假设第一行是标题行
                ExcelReader reader = ExcelUtil.getReader(file);
                // 读取所有行，每行作为Map<String, Object>返回，列名来自文件
                List<Map<String, Object>> rows = reader.readAll();
                // 遍历所有行
                for (Map<String, Object> row : rows) {
                    String method = (String) row.get("方法");
                    String host = (String) row.get("主机");
                    String path = (String) row.get("路径");
                    System.out.println("主机: " + host + ", 路径: " + path);
//                    addUrl()
                }

                // 关闭reader
                reader.close();
                return null;
            }

            @Override
            protected void done() {
                try {
                    List<Object[]> taskStatusList = get();
                    if (!taskStatusList.isEmpty()) {
//                        JOptionPane.showMessageDialog(Databoard.this, generateTaskStatusPane(taskStatusList), "Info", JOptionPane.INFORMATION_MESSAGE);
                    }
                } catch (Exception ignored) {
                }
            }
        };

        importActionWorker.execute();
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse iHttpRequestResponse) {
        if (isPassiveScan && validListenerEnabled(toolFlag) && !messageIsRequest) {
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
        List<ZacConfigBean> domain = getConfigListsByType("domain");
        // 将domain转为List<String>
        domainList = new ArrayList<>();
        for (ZacConfigBean zacConfigBean : domain) {
            domainList.add(zacConfigBean.getValue());
        }

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

        // 保存API测试结果数据
        saveAPIDataButton.addActionListener(e -> {
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

        // 导入API数据
        importAPIDataButton.addActionListener(this::importActionPerformed);

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
                    saveConfig(zacConfigBean);
                }
            } else {
                if (whiteListTextAreaText.isEmpty()) {
                    return;
                }
                ZacConfigBean zacConfigBean = new ZacConfigBean("domain", whiteListTextAreaText);
                saveConfig(zacConfigBean);
            }
            List<ZacConfigBean> domain = getConfigListsByType("domain");
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

        // 是否收集响应体选择框事件
        collectResponseCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                isCollectResponse = collectResponseCheckBox.isSelected();
            }
        });

        collectResponseCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                isCollectUnique = collectResponseCheckBox.isSelected();
            }
        });

        // 数据库获取白名单域名,输出到面板
        List<ZacConfigBean> domains = getConfigListsByType("domain");
        for (ZacConfigBean zacConfigBean : domains) {
            // 如果是最后一个，就不加换行符
            if (domains.indexOf(zacConfigBean) == domains.size() - 1) {
                whiteListTextArea.setText(whiteListTextArea.getText() + zacConfigBean.getValue());
                break;
            }
            whiteListTextArea.setText(whiteListTextArea.getText() + zacConfigBean.getValue() + "\n");
        }

        List<ZacConfigBean> methods = getConfigListsByType("method");
        for (ZacConfigBean zacConfigBean : methods) {
            if (Objects.equals(zacConfigBean.getValue(), "GET")) collectGETCheckBox.setSelected(true);
            if (Objects.equals(zacConfigBean.getValue(), "POST")) collectPOSTCheckBox.setSelected(true);
            if (Objects.equals(zacConfigBean.getValue(), "PUT")) collectPUTCheckBox.setSelected(true);
            if (Objects.equals(zacConfigBean.getValue(), "DELETE")) collectDELETECheckBox.setSelected(true);
            if (Objects.equals(zacConfigBean.getValue(), "HEAD")) collectHEADCheckBox.setSelected(true);
            if (Objects.equals(zacConfigBean.getValue(), "OPTIONS")) collectOPTIONSCheckBox.setSelected(true);
            if (Objects.equals(zacConfigBean.getValue(), "TRACE")) collectTRACECheckBox.setSelected(true);
            if (Objects.equals(zacConfigBean.getValue(), "CONNECT")) collectCONNECTCheckBox.setSelected(true);
        }

        List<ZacConfigBean> listeners = getConfigListsByType("listener");
        for (ZacConfigBean zacConfigBean : listeners) {
            if (Objects.equals(zacConfigBean.getValue(), "Proxy")) proxyToolCheckBox.setSelected(true);
            if (Objects.equals(zacConfigBean.getValue(), "Comparer")) comparerToolCheckBox.setSelected(true);
            if (Objects.equals(zacConfigBean.getValue(), "Decoder")) decoderToolCheckBox.setSelected(true);
            if (Objects.equals(zacConfigBean.getValue(), "Extender")) extenderToolCheckBox.setSelected(true);
            if (Objects.equals(zacConfigBean.getValue(), "Intruder")) intruderToolCheckBox.setSelected(true);
            if (Objects.equals(zacConfigBean.getValue(), "Repeater")) repeaterToolCheckBox.setSelected(true);
            if (Objects.equals(zacConfigBean.getValue(), "Scanner")) scannerToolCheckBox.setSelected(true);
            if (Objects.equals(zacConfigBean.getValue(), "Sequencer")) sequencerToolCheckBox.setSelected(true);
            if (Objects.equals(zacConfigBean.getValue(), "Spider")) spiderToolCheckBox.setSelected(true);
            if (Objects.equals(zacConfigBean.getValue(), "Suite")) suiteToolCheckBox.setSelected(true);
            if (Objects.equals(zacConfigBean.getValue(), "Target")) targetToolCheckBox.setSelected(true);
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
        urltable.getColumnModel().getColumn(3).setCellRenderer(renderer);

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
        // 导出Xlsx按钮
        saveAPIDataButton = new JButton("导出测试结果");
        // 导入Xlsx按钮
        importAPIDataButton = new JButton("导入接口列表");
        // 白名单域名输入框列表
        whiteListTextArea = new JTextArea(5, 10);
        whiteListTextArea.setLineWrap(false); // 自动换行
        whiteListTextArea.setWrapStyleWord(false); // 按单词换行
        JScrollPane whiteListTextAreascrollPane = new JScrollPane(whiteListTextArea);

        // 刷新表格按钮
        refreshTableButton = new JButton("刷新表格");
        // 清空表格按钮
        clearTableButton = new JButton("清空表格");
        // 白名单域名label
        JLabel whiteDomainListLabel = new JLabel("白名单域名");
        // 收集方法范围 label
        JLabel methodLabel = new JLabel("收集方法范围");
        collectGETCheckBox = new JCheckBox("GET");
        collectPOSTCheckBox = new JCheckBox("POST");
        collectPUTCheckBox = new JCheckBox("PUT");
        collectDELETECheckBox = new JCheckBox("DELETE");
        collectHEADCheckBox = new JCheckBox("HEAD");
        collectOPTIONSCheckBox = new JCheckBox("OPTIONS");
        collectTRACECheckBox = new JCheckBox("TRACE");
        collectCONNECTCheckBox = new JCheckBox("CONNECT");

        // 添加到右边的上部分
        JPanel rightTopPanel = new JPanel();
        rightTopPanel.setLayout(new GridBagLayout());
        rightTopPanel.add(passiveScanCheckBox, new GridBagConstraintsHelper(0, 0, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(checkWhiteListCheckBox, new GridBagConstraintsHelper(0, 1, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(collectResponseCheckBox, new GridBagConstraintsHelper(1, 1, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(saveAPIDataButton, new GridBagConstraintsHelper(0, 2, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
//        rightTopPanel.add(importAPIDataButton, new GridBagConstraintsHelper(1, 2, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(refreshTableButton, new GridBagConstraintsHelper(0, 3, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(clearTableButton, new GridBagConstraintsHelper(1, 3, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(whiteDomainListLabel, new GridBagConstraintsHelper(0, 4, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(saveWhiteListButton, new GridBagConstraintsHelper(1, 4, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(whiteListTextAreascrollPane, new GridBagConstraintsHelper(0, 5, 3, 1).setInsets(5).setIpad(0, 0).setWeight(1.0, 1.0).setAnchor(GridBagConstraints.CENTER).setFill(GridBagConstraints.BOTH));
        rightTopPanel.add(methodLabel, new GridBagConstraintsHelper(0, 6, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(collectGETCheckBox, new GridBagConstraintsHelper(0, 7, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(collectPOSTCheckBox, new GridBagConstraintsHelper(1, 7, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(collectPUTCheckBox, new GridBagConstraintsHelper(0, 8, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(collectDELETECheckBox, new GridBagConstraintsHelper(1, 8, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(collectOPTIONSCheckBox, new GridBagConstraintsHelper(0, 9, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(collectHEADCheckBox, new GridBagConstraintsHelper(1, 9, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(collectTRACECheckBox, new GridBagConstraintsHelper(0, 10, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(collectCONNECTCheckBox, new GridBagConstraintsHelper(1, 10, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));

        rightSplitPane.setTopComponent(rightTopPanel);

        // 右边的下部分左边
        // 监听配置 label
        JLabel listenerConfigLabel = new JLabel("监听范围配置");
        saveListenerConfigButton = new JButton("保存监听配置");
        comparerToolCheckBox = new JCheckBox("对比(Comparer)");
        decoderToolCheckBox = new JCheckBox("编码(Decoder)");
        extenderToolCheckBox = new JCheckBox("插件(Extender)");
        intruderToolCheckBox = new JCheckBox("测试(Intruder)");
        proxyToolCheckBox = new JCheckBox("代理(Proxy)");
        repeaterToolCheckBox = new JCheckBox("重放(Repeater)");
        scannerToolCheckBox = new JCheckBox("扫描(Scanner)");
        sequencerToolCheckBox = new JCheckBox("定序(Sequencer)");
        spiderToolCheckBox = new JCheckBox("爬虫(Spider)");
        suiteToolCheckBox = new JCheckBox("程序(Suite)");
        targetToolCheckBox = new JCheckBox("目标(Target)");

        JPanel rightDownLeftPanel = new JPanel();
        rightDownLeftPanel.setLayout(new GridBagLayout());
        rightDownLeftPanel.add(listenerConfigLabel, new GridBagConstraintsHelper(0, 0, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightDownLeftPanel.add(proxyToolCheckBox, new GridBagConstraintsHelper(0, 1, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightDownLeftPanel.add(comparerToolCheckBox, new GridBagConstraintsHelper(1, 1, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightDownLeftPanel.add(decoderToolCheckBox, new GridBagConstraintsHelper(0, 2, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightDownLeftPanel.add(extenderToolCheckBox, new GridBagConstraintsHelper(1, 2, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightDownLeftPanel.add(intruderToolCheckBox, new GridBagConstraintsHelper(0, 3, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightDownLeftPanel.add(repeaterToolCheckBox, new GridBagConstraintsHelper(1, 3, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightDownLeftPanel.add(scannerToolCheckBox, new GridBagConstraintsHelper(0, 4, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightDownLeftPanel.add(sequencerToolCheckBox, new GridBagConstraintsHelper(1, 4, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightDownLeftPanel.add(spiderToolCheckBox, new GridBagConstraintsHelper(0, 5, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightDownLeftPanel.add(suiteToolCheckBox, new GridBagConstraintsHelper(1, 5, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightDownLeftPanel.add(targetToolCheckBox, new GridBagConstraintsHelper(0, 6, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
//        rightDownLeftPanel.add(saveListenerConfigButton, new GridBagConstraintsHelper(0, 7, 2, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightSplitPane.setBottomComponent(rightDownLeftPanel);

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

    /**
     * 校验是否勾选指定的监听模块
     *
     * @param msgType 模块的类型编号
     * @return true:已勾选 false:未勾选
     */
    public boolean validListenerEnabled(int msgType) {
        switch (msgType) {
            case IBurpExtenderCallbacks.TOOL_COMPARER:
                return comparerToolCheckBox.isSelected();
            case IBurpExtenderCallbacks.TOOL_DECODER:
                return decoderToolCheckBox.isSelected();
            case IBurpExtenderCallbacks.TOOL_EXTENDER:
                return extenderToolCheckBox.isSelected();
            case IBurpExtenderCallbacks.TOOL_INTRUDER:
                return intruderToolCheckBox.isSelected();
            case IBurpExtenderCallbacks.TOOL_PROXY:
                return proxyToolCheckBox.isSelected();
            case IBurpExtenderCallbacks.TOOL_REPEATER:
                return repeaterToolCheckBox.isSelected();
            case IBurpExtenderCallbacks.TOOL_SCANNER:
                return scannerToolCheckBox.isSelected();
            case IBurpExtenderCallbacks.TOOL_SEQUENCER:
                return sequencerToolCheckBox.isSelected();
            case IBurpExtenderCallbacks.TOOL_SPIDER:
                return spiderToolCheckBox.isSelected();
            case IBurpExtenderCallbacks.TOOL_SUITE:
                return suiteToolCheckBox.isSelected();
            case IBurpExtenderCallbacks.TOOL_TARGET:
                return targetToolCheckBox.isSelected();
        }
        return false;
    }

    // url 实体类
    @Data
    public static class UrlEntry {
        final int id;
        final String method;
        final String url;
        final String host;
        final String path;
        final int length;
        final int counts;
        final String status;
        final IHttpRequestResponse requestResponse;

        UrlEntry(int id, String method, String host, String path, String url, int length, int counts, String status, IHttpRequestResponse requestResponse) {
            this.id = id;
            this.method = method;
            this.url = url;
            this.path = path;
            this.host = host;
            this.length = length;
            this.counts = counts;
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
            return 6;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            switch (columnIndex) {
                case 0:
                    return urldata.get(rowIndex).id;
                case 1:
                    return urldata.get(rowIndex).method;
                case 2:
                    return urldata.get(rowIndex).host;
                case 3:
                    return urldata.get(rowIndex).path;
                case 4:
                    return urldata.get(rowIndex).counts;
                case 5:
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
                    return "Host";
                case 3:
                    return "Path";
                case 4:
                    return "Counts";
                case 5:
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