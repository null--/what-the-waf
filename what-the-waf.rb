require 'java'

# JAVAX
java_import 'java.awt.Color'
java_import 'java.awt.Dimension'
java_import 'java.awt.event.ActionListener'
java_import 'java.awt.BorderLayout'
java_import 'java.awt.FlowLayout'
java_import 'java.awt.Container'
java_import 'javax.swing.JTable'
java_import 'javax.swing.table.DefaultTableModel'
java_import 'javax.swing.DefaultListModel'
java_import 'javax.swing.JPanel'
java_import 'javax.swing.JTabbedPane'
java_import 'javax.swing.JButton'
java_import 'javax.swing.JScrollBar'
java_import 'javax.swing.JOptionPane'
java_import 'javax.swing.JEditorPane'
java_import 'javax.swing.JCheckBox'
java_import 'javax.swing.JRadioButton'
java_import 'javax.swing.ButtonGroup'
java_import 'javax.swing.JTextField'
java_import 'javax.swing.JTextArea'
java_import 'javax.swing.JLabel'
java_import 'javax.swing.JFileChooser'
java_import 'javax.swing.filechooser.FileFilter'
java_import 'javax.swing.JList'
java_import 'javax.swing.JSplitPane'
java_import 'javax.swing.JScrollPane'
java_import 'javax.swing.Box'
java_import 'javax.swing.BoxLayout'
java_import 'javax.swing.JSpinner'
java_import 'javax.swing.BoxLayout'
java_import 'javax.swing.SwingConstants'
java_import 'javax.swing.BorderFactory'
java_import 'javax.swing.GroupLayout'
java_import 'javax.swing.SpringLayout'
java_import 'javax.swing.event.ChangeListener'
java_import 'javax.swing.border.LineBorder'
java_import 'javax.swing.border.EmptyBorder'
java_import 'javax.swing.border.TitledBorder'

# BURP
java_import 'burp.IBurpExtender'
java_import 'burp.IHttpListener'
java_import 'burp.IHttpRequestResponse'
java_import 'burp.IHttpService'
java_import 'burp.IExtensionHelpers'
java_import 'burp.ITab'
java_import 'burp.IMenuItemHandler'

class WordlistFilter < FileFilter
  
  def getDescription
    "Line-seperated wordlist file (*.lst, *.txt)"
  end
  
  def accept(_f)
    # JOptionPane.showMessageDialog(nil, _f)
    return true if not File.file?(_f.to_s)
    return true if File.extname(_f.to_s).downcase == ".txt"
    return true if File.extname(_f.to_s).downcase == ".lst"
    false
  end
end

class BurpExtender
  include IBurpExtender, IExtensionHelpers
  include IHttpService, IHttpListener, IHttpRequestResponse
  include ITab, IMenuItemHandler

  def registerExtenderCallbacks(_burp)
    @started = false
        
    # init
    @burp = _burp
    @burp.setExtensionName("What the WAF?!")
    @helpers = @burp.getHelpers()
    
    # gui
    # # tabs
    @tabs = JTabbedPane.new()
    
    initTargetUI
    initResultUI
    initPayloads

    @burp.customizeUiComponent(@tabs)
    @burp.addSuiteTab(self)
    
    # # menu
    @burp.registerMenuItem("Send to what-the-waf", self)
  end

  def getTabCaption
    return "What the WAF?!"
  end

  def getUiComponent
    return @tabs
  end

  def initTargetUI
    container = JPanel.new()
    @tab_tgt = @tabs.addTab("Target", container)
    
    container.setLayout(BorderLayout.new())
    container.setBorder(EmptyBorder.new( 3, 3, 3, 3 ) )
    @pan_tgt = JPanel.new()
    @lay_tgt = GroupLayout.new(@pan_tgt)
    @pan_tgt.setLayout(@lay_tgt)
    scroll = JScrollPane.new(@pan_tgt)
    container.add(scroll, BorderLayout::CENTER)
    
    # # START BTN # #
    @btn_start = JButton.new("<html><h1><font color='green'>Start</font><h1><html>")
    
    # # INFO PANEL # #
    @pan_info = JPanel.new()
    @lay_info = GroupLayout.new(@pan_info)
    @pan_info.setBorder(BorderFactory.createMatteBorder(0,0,2,0, Color.orange))
    lbl_info = JLabel.new("<html><h3>General Target Info</h3></html>")
    @pan_info.setLayout(@lay_info)
    # @txt_url.setBorder(BorderFactory.createLineBorder(Color.black, 1, true))
    lbl_req = JLabel.new("Baseline Request")
    @txt_req = JTextArea.new("Inside burp right-click on a http request and select 'send to what-the-waf'")
    @txt_req_scr = JScrollPane.new(@txt_req)
    lbl_param = JLabel.new("Parameter")
    @txt_param = JTextField.new("wtwtest")
    lbl_param_inf = JLabel.new("<html><i>This parameter can be imaginary!</i></html>")
    
    @lay_info.setAutoCreateGaps(true)
    @lay_info.setAutoCreateContainerGaps(true)
    
    @lay_info.setHorizontalGroup(
      @lay_info.createParallelGroup(GroupLayout::Alignment::LEADING
        ).addComponent(lbl_info
        ).addComponent(lbl_req
        ).addComponent(@txt_req_scr, 600, 600, 600
        ).addGroup(@lay_info.createSequentialGroup(
          ).addComponent(lbl_param
          ).addComponent(@txt_param, 100, 100, 100)
        ).addComponent(lbl_param_inf)
    )
    
    @lay_info.setVerticalGroup(
      @lay_info.createSequentialGroup(
        ).addComponent(lbl_info
        ).addComponent(lbl_req
        ).addComponent(@txt_req_scr, 200, 200, 200
        ).addGroup(@lay_info.createParallelGroup(GroupLayout::Alignment::BASELINE
          ).addComponent(lbl_param
          ).addComponent(@txt_param)
        ).addComponent(lbl_param_inf)
    )
    
    # # WAF PANEL # #
    @pan_waf = JPanel.new()
    @lay_waf = GroupLayout.new(@pan_waf)
    @pan_waf.setLayout(@lay_waf)
    @pan_waf.setBorder(BorderFactory.createMatteBorder(0,0,2,0, Color.orange))
    lbl_waf = JLabel.new("<html><h3>WAF Options</h3></html>")
    
    lbl_hcode = JLabel.new("<html><b>WAF HTTP RSP CODE</b><br><i>HTTP response code(s) used by WAF to block malicious requests</i></html>")
    @chk_200 = JCheckBox.new("<html>200: OK (WAF was configured to show a <i>\"block\" page</i> <b>directly</b>)")
    @chk_301 = JCheckBox.new("301: Moved Permanently")
    @chk_302 = JCheckBox.new("302: Found")
    @chk_400 = JCheckBox.new("400: Bad Request")
    @chk_401 = JCheckBox.new("401: Unauthorized")
    @chk_403 = JCheckBox.new("403: Forbidden")
    @chk_404 = JCheckBox.new("404: Not Found")
    @chk_500 = JCheckBox.new("500: Internal Server Error")
    @chk_502 = JCheckBox.new("502: Bad Gateway")
    @chk_503 = JCheckBox.new("503: Service Unavailable")
    @chk_504 = JCheckBox.new("504: Gateway Timeout")
    lbl_red = JLabel.new("<html><br><b>WAF Block/Redirection URL</b><br><i>After being detected, Where does WAF redirect you?</i></html>")
    lbl_block_url = JLabel.new("Block/Redirection URL")
    @txt_block_url = JTextField.new()
    lbl_timeout = JLabel.new("Block timeout")
    @txt_timeout = JTextField.new()
    lbl_timeout_info = JLabel.new("<html><i>The connection timeout value used by WAF to block a malicious client. (in seconds)</i></html>")
    @lay_waf.setHorizontalGroup(
      @lay_waf.createParallelGroup(GroupLayout::Alignment::LEADING
        ).addComponent(lbl_waf
        ).addComponent(lbl_hcode
        ).addComponent(@chk_200
        ).addComponent(@chk_301
        ).addComponent(@chk_302
        ).addComponent(@chk_400
        ).addComponent(@chk_401
        ).addComponent(@chk_403
        ).addComponent(@chk_404
        ).addComponent(@chk_500
        ).addComponent(@chk_502
        ).addComponent(@chk_503
        ).addComponent(@chk_504
        ).addComponent(lbl_red
        ).addGroup(@lay_waf.createSequentialGroup(
          ).addComponent(lbl_block_url
          ).addComponent(@txt_block_url, 300, 500, 600)
        ).addGroup(@lay_waf.createSequentialGroup(
          ).addComponent(lbl_timeout
          ).addComponent(@txt_timeout, 100, 100, 100)
        ).addComponent(lbl_timeout_info)
    )
    
    @lay_waf.setVerticalGroup(
      @lay_waf.createSequentialGroup(
        ).addComponent(lbl_waf
        ).addComponent(lbl_hcode
        ).addComponent(@chk_200
        ).addComponent(@chk_301
        ).addComponent(@chk_302
        ).addComponent(@chk_400
        ).addComponent(@chk_401
        ).addComponent(@chk_403
        ).addComponent(@chk_404
        ).addComponent(@chk_500
        ).addComponent(@chk_502
        ).addComponent(@chk_503
        ).addComponent(@chk_504
        ).addComponent(lbl_red
        ).addGroup(@lay_waf.createParallelGroup(GroupLayout::Alignment::BASELINE
          ).addComponent(lbl_block_url
          ).addComponent(@txt_block_url)
        ).addGroup(@lay_waf.createParallelGroup(GroupLayout::Alignment::BASELINE
          ).addComponent(lbl_timeout
          ).addComponent(@txt_timeout)
        ).addComponent(lbl_timeout_info)
    )
    
    # # PAYLOAD PANEL # #
    @pan_pay = JPanel.new()
    @lay_pay = GroupLayout.new(@pan_pay)
    @pan_pay.setLayout(@lay_pay)
    @pan_pay.setBorder(BorderFactory.createMatteBorder(0,0,2,0, Color.orange))
    lbl_pay = JLabel.new("<html><h3>Payload Options</h3></html>")
    lbl_sel = JLabel.new("<html><b>Wordlist</b><br><i>Note: Selected wordlist files will be reloaded, each time you hit the \"Start\" button.\"<br>Multi-selection was enabled</i></html>")
    @lst_pay_model = DefaultListModel.new()
    @lst_pay = JList.new(@lst_pay_model)
    @lst_pay_scr = JScrollPane.new(@lst_pay)
    lbl_pay_add = JLabel.new("<html><i>Add new wordlist (line-seperated list of paylaods)</i></html>")
    @btn_pay_add = JButton.new("Add")
    lbl_cont = JLabel.new("<html><br><b>Payload Factory</b></html>")
    lbl_min_pay_size = JLabel.new("Minimum payload size")
    @txt_min_pay_size = JTextField.new("0")
    lbl_max_pay_size = JLabel.new("Maximum payload size")
    @txt_max_pay_size = JTextField.new("256")
    lbl_pay_size_info = JLabel.new("<html><i>Maximum and Minimum payload size can be equivalent.<br></i></html>")
    lbl_pay_pat = JLabel.new("Pattern")
    @txt_pay_pat = JTextField.new("%20")
    lbl_pay_pat_info = JLabel.new("<html><i>If the payload length be less than the \"Minimum payload size\", this pattern will be used to increase the size of payload.<br></i></html>")
    lbl_pat_grp = JLabel.new("<html><br><b>Prefix/Suffix</b></html>")
    @rdo_pat_left = JRadioButton.new("Treat the pattern as prefix")
    @rdo_pat_right = JRadioButton.new("Treat the pattern as suffix")
    @rdo_pat_both = JRadioButton.new("Both!")
    grp_pat = ButtonGroup.new()
    grp_pat.add(@rdo_pat_left)
    grp_pat.add(@rdo_pat_right)
    grp_pat.add(@rdo_pat_both)
    
    @lay_pay.setHorizontalGroup(
      @lay_pay.createParallelGroup(GroupLayout::Alignment::LEADING
        ).addComponent(lbl_pay
        ).addComponent(lbl_sel
        ).addComponent(@lst_pay_scr, 200, 300, 300
        ).addComponent(lbl_pay_add
        ).addComponent(@btn_pay_add
        ).addComponent(lbl_cont
        ).addGroup(@lay_pay.createSequentialGroup(
          ).addComponent(lbl_min_pay_size
          ).addComponent(@txt_min_pay_size, 100, 100, 100)
        ).addGroup(@lay_pay.createSequentialGroup(
          ).addComponent(lbl_max_pay_size
          ).addComponent(@txt_max_pay_size, 100, 100, 100)
        ).addComponent(lbl_pay_size_info
        ).addGroup(@lay_pay.createSequentialGroup(
          ).addComponent(lbl_pay_pat
          ).addComponent(@txt_pay_pat,300,300,300)
        ).addComponent(lbl_pay_pat_info
        ).addComponent(lbl_pat_grp
        ).addComponent(@rdo_pat_left
        ).addComponent(@rdo_pat_right
        ).addComponent(@rdo_pat_both)
    )
    
    @lay_pay.setVerticalGroup(
      @lay_pay.createSequentialGroup(
        ).addComponent(lbl_pay
        ).addComponent(lbl_sel
        ).addComponent(@lst_pay_scr, 100, 200, 200
        ).addComponent(lbl_pay_add
        ).addComponent(@btn_pay_add
        ).addComponent(lbl_cont
        ).addGroup(@lay_pay.createParallelGroup(GroupLayout::Alignment::BASELINE
          ).addComponent(lbl_min_pay_size
          ).addComponent(@txt_min_pay_size)
        ).addGroup(@lay_pay.createParallelGroup(GroupLayout::Alignment::BASELINE
          ).addComponent(lbl_max_pay_size
          ).addComponent(@txt_max_pay_size)
        ).addComponent(lbl_pay_size_info
        ).addGroup(@lay_pay.createParallelGroup(GroupLayout::Alignment::BASELINE
          ).addComponent(lbl_pay_pat
          ).addComponent(@txt_pay_pat)
        ).addComponent(lbl_pay_pat_info
        ).addComponent(lbl_pat_grp
        ).addComponent(@rdo_pat_left
        ).addComponent(@rdo_pat_right
        ).addComponent(@rdo_pat_both)
    )
        
    # # SCAN PANEL # #
    @pan_scan = JPanel.new()
    @lay_scan = GroupLayout.new(@pan_scan)
    @pan_scan.setLayout(@lay_scan)
    @pan_scan.setBorder(BorderFactory.createMatteBorder(0,0,2,0, Color.orange))
    lbl_scan = JLabel.new("<html><h3>Scan Options</h3></html>")
    @chk_encode = JCheckBox.new("Force html encoding")
    lbl_scan_ses = JLabel.new("<html><b>Session Settings</b></html>")
    lbl_delay = JLabel.new("Delay")
    lbl_scan_cont = JLabel.new("<html><br><b>Content Settings</b></html>")
    @txt_delay = JTextField.new("0")
    
    @lay_scan.setHorizontalGroup(
      @lay_scan.createParallelGroup(GroupLayout::Alignment::LEADING
        ).addComponent(lbl_scan
        ).addComponent(lbl_scan_ses
        ).addGroup(@lay_scan.createSequentialGroup(
          ).addComponent(lbl_delay
          ).addComponent(@txt_delay, 100, 100, 100)
        ).addComponent(lbl_scan_cont
        ).addComponent(@chk_encode)
    )
    
    @lay_scan.setVerticalGroup(
      @lay_scan.createSequentialGroup(
        ).addComponent(lbl_scan
        ).addComponent(lbl_scan_ses
        ).addGroup(@lay_scan.createParallelGroup(GroupLayout::Alignment::BASELINE
          ).addComponent(lbl_delay
          ).addComponent(@txt_delay)
        ).addComponent(lbl_scan_cont
        ).addComponent(@chk_encode)
    )
    
    # Finalize layout
    @lay_tgt.setHorizontalGroup(
      @lay_tgt.createParallelGroup(GroupLayout::Alignment::LEADING
        ).addComponent(@pan_info
        ).addComponent(@pan_waf
        ).addComponent(@pan_pay
        ).addComponent(@pan_scan
        ).addComponent(@btn_start)
    )
    
    @lay_tgt.setVerticalGroup(
      @lay_tgt.createSequentialGroup(
        ).addComponent(@pan_info
        ).addComponent(@pan_waf
        ).addComponent(@pan_pay
        ).addComponent(@pan_scan
        ).addComponent(@btn_start)
    )
    
    # Add Action Listeners
    @btn_start.addActionListener do |e|
      wtwStart
    end
    
    @btn_pay_add.addActionListener do |e|
      addPayload
    end
  end

  def initResultUI
    container = JPanel.new()
    @tab_pl  = @tabs.addTab("Result", container)
    
    container.setLayout(BorderLayout.new())
    container.setBorder(EmptyBorder.new( 3, 3, 3, 3 ) )
    @pan_res = JPanel.new()
    @lay_res = GroupLayout.new(@pan_res)
    @pan_res.setLayout(@lay_res)
    # scroll = JScrollPane.new(@pan_res)
    # container.add(scroll, BorderLayout::CENTER)
    container.add(@pan_res, BorderLayout::CENTER)
    
    lbl_passed = JLabel.new("<html><i>Below, is a list of <b>passed</b> payloads.</i></html>")
    @tbl_res_model = DefaultTableModel.new()
    @tbl_res_model.addColumn("#")
    @tbl_res_model.addColumn("wordlist")
    @tbl_res_model.addColumn("payload")
    @tbl_res = JTable.new(@tbl_res_model)
    scroll_tbl = JScrollPane.new(@tbl_res)
    @tbl_res.setFillsViewportHeight(true);
    @tbl_res.getColumnModel().getColumn(0).setPreferredWidth(50)
    @tbl_res.getColumnModel().getColumn(1).setPreferredWidth(300)
    @tbl_res.getColumnModel().getColumn(2).setPreferredWidth(900)
    @tbl_res.setAutoResizeMode(JTable::AUTO_RESIZE_OFF)
    
    @lay_res.setHorizontalGroup(
      @lay_res.createParallelGroup(GroupLayout::Alignment::LEADING
        ).addComponent(lbl_passed
        ).addComponent(scroll_tbl)
    )
    
    @lay_res.setVerticalGroup(
      @lay_res.createSequentialGroup(
        ).addComponent(lbl_passed
        ).addComponent(scroll_tbl)
    )
  end
  
  def initPayloads
    paydir = File.expand_path(File.dirname(__FILE__)) + "/payloads/"
    # JOptionPane.showMessageDialog(nil, paydir)
    @wordlist = {}
    Dir.glob(paydir+ "*.lst") do |p|
      #JOptionPane.showMessageDialog(nil, p)
      #if File.extname(p) == ".lst" then
        @wordlist[File.basename(p, ".*")] = p
        @lst_pay_model.addElement(File.basename(p, ".*"))
      #end
    end
  end
  
  def addPayload
    fc = JFileChooser.new()
    fc.setFileFilter(WordlistFilter.new())
    if fc.showOpenDialog(@tabs) == JFileChooser::APPROVE_OPTION then
      p = fc.getSelectedFile().to_s
      # TODO: Check for duplicates
      @wordlist[File.basename(p, ".*")] = p
      @lst_pay_model.addElement(File.basename(p, ".*"))
    end
  end
  
  def wtwStart
    if not @started then
      @btn_start.setText("<html><h1><font color='red'>Stop</font><h1><html>")
    else
      @btn_start.setText("<html><h1><font color='green'>Start</font><h1><html>")
    end
    @started = (not @started)
  end
  
  def menuItemClicked(caption, msg_info)
    JOptionPane.showMessageDialog(nil, msg_info[0].getRequest().to_s)
    @txt_req.setText(msg_info[0].getRequest().to_s)
  end
end
