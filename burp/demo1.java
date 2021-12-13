package burp;

import javax.swing.table.AbstractTableModel;
import java.io.PrintWriter;

public class demo1 extends AbstractTableModel implements IBurpExtender
{
    //
    // implement IBurpExtender
    //

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // set our extension name
//        callbacks.setExtensionName("Hello world extension");
//
//        // obtain our output and error streams
//        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
//        PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
//
//        // write a message to our output stream
//        stdout.println("Hello output");
//
//
//
//        callbacks.issueAlert("Hello alerts");

        // throw an exception that will appear in our error stream
//        throw new RuntimeException("Hello exceptions");
    }

    @Override
    public int getRowCount() {
        return 0;
    }

    @Override
    public int getColumnCount() {
        return 0;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        return null;
    }
}