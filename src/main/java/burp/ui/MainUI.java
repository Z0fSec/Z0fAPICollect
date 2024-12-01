package burp.ui;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import burp.utils.Utils;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;


public class MainUI extends JPanel implements ITab {
    private static JTabbedPane mainPanel;
    IBurpExtenderCallbacks callbacks;

    public MainUI(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        try {
            mainPanel = new JTabbedPane();
            for (int i = 0; i < init().size(); i++) {
                Class<?> clazz = Class.forName(init().get(i));
                UIHandler uiHandler = (UIHandler) clazz.newInstance();
                uiHandler.init();
                mainPanel.add(uiHandler.getTabName(), uiHandler.getPanel(callbacks));
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
    }

    public static List<String> init() {
        List<String> uiList = new ArrayList<>();
        uiList.add("burp.ui.APICollectUI");
        uiList.add("burp.ui.APICheckUI");
        return uiList;
    }

    @Override
    public String getTabCaption() {
        return Utils.NAME;
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }

}