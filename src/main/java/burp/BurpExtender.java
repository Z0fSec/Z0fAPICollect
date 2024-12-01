package burp;

import burp.menu.APICollectMenu;
import burp.menu.TextProcessMenu;
import burp.ui.MainUI;
import burp.utils.Utils;

import javax.swing.*;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class BurpExtender implements IBurpExtender, IContextMenuFactory, IHttpListener {
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        Utils.callbacks = iBurpExtenderCallbacks;
        Utils.helpers = iBurpExtenderCallbacks.getHelpers();
        Utils.stdout = new PrintWriter(iBurpExtenderCallbacks.getStdout(), true);
        Utils.stderr = new PrintWriter(iBurpExtenderCallbacks.getStderr(), true);
        Utils.callbacks.setExtensionName(Utils.NAME);
        Utils.callbacks.registerContextMenuFactory(this);
        Utils.callbacks.registerHttpListener(this);
        MainUI mainUI = new MainUI(Utils.callbacks);
        Utils.callbacks.addSuiteTab(mainUI);
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                Utils.callbacks.customizeUiComponent(mainUI);
            }
        });
        Utils.stdout.println("################################################");
        Utils.stdout.println("[#]  Load Successfully");
        Utils.stdout.println("[#]  Z0fAPICollect v" + Utils.VERSION);
        Utils.stdout.println("[#]  Author: EatMans@Z0fSec");
        Utils.stdout.println("[#]  Email: z0fsec@163.com");
        Utils.stdout.println("[#]  Github: https://github.com/Z0fSec/Z0fAPICollect");
        Utils.stdout.println("################################################");
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation iContextMenuInvocation) {
        List<JMenuItem> listMenuItems = new ArrayList<JMenuItem>(1);
        IHttpRequestResponse[] requestResponses = iContextMenuInvocation.getSelectedMessages();
        IHttpRequestResponse baseRequestResponse = iContextMenuInvocation.getSelectedMessages()[0];
        // 如果是个空的, 则返回null
        if (baseRequestResponse.getHttpService() == null) {
            return null;
        }
        listMenuItems.add(new APICollectMenu(requestResponses));
        listMenuItems.add(new TextProcessMenu(iContextMenuInvocation));
        return listMenuItems;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER && messageIsRequest) {
            byte[] request = messageInfo.getRequest();
            String requestStr = Utils.helpers.bytesToString(request);
            if (requestStr.contains("<datab64>")) {
                // 解码 base64 数据
                String data = requestStr.substring(requestStr.indexOf("<datab64>") + 9, requestStr.indexOf("</datab64>"));
                byte[] decodedData = Base64.getDecoder().decode(data);

                // 构建新的请求体
                byte[] newBytes = new byte[requestStr.indexOf("<datab64>") + decodedData.length + (request.length - requestStr.indexOf("</datab64>") - 10)];
                System.arraycopy(request, 0, newBytes, 0, requestStr.indexOf("<datab64>"));
                System.arraycopy(decodedData, 0, newBytes, requestStr.indexOf("<datab64>"), decodedData.length);
                System.arraycopy(request, requestStr.indexOf("</datab64>") + 10, newBytes, requestStr.indexOf("<datab64>") + decodedData.length, request.length - requestStr.indexOf("</datab64>") - 10);

                // 更新 Content-Length
                IRequestInfo analyzedRequest = Utils.helpers.analyzeRequest(newBytes);
                List<String> headers = new ArrayList<>(analyzedRequest.getHeaders());
                int bodyOffset = analyzedRequest.getBodyOffset();
                int contentLength = newBytes.length - bodyOffset;

                // 更新或添加 Content-Length 头
                boolean contentLengthFound = false;
                for (int i = 0; i < headers.size(); i++) {
                    if (headers.get(i).startsWith("Content-Length:")) {
                        headers.set(i, "Content-Length: " + contentLength);
                        contentLengthFound = true;
                        break;
                    }
                }
                if (!contentLengthFound) {
                    headers.add("Content-Length: " + contentLength);
                }

                // 重建请求
                byte[] body = new byte[newBytes.length - bodyOffset];
                System.arraycopy(newBytes, bodyOffset, body, 0, body.length);
                byte[] updatedRequest = Utils.helpers.buildHttpMessage(headers, body);

                messageInfo.setRequest(updatedRequest);
            }
        }
    }

}
