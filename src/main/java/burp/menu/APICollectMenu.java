package burp.menu;

import burp.IHttpRequestResponse;
import burp.ui.APICollectUI;

import javax.swing.*;
import java.awt.event.ActionListener;

public class APICollectMenu extends JMenuItem {
    public APICollectMenu(IHttpRequestResponse[] requestResponses) {
        this.setText("API Collect");
        this.addActionListener(new ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        APICollectUI.Collect(requestResponses, true);
                    }
                });
                thread.start();
            }
        });
    }
}
