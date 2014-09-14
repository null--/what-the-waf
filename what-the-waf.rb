require 'java'

# JAVA/JAVAX
java_import 'java.awt.Color'
java_import 'java.awt.Dimension'
java_import 'java.awt.event.ActionListener'
java_import 'java.awt.BorderLayout'
java_import 'java.awt.FlowLayout'
java_import 'java.awt.GridLayout'
java_import 'java.awt.Container'
java_import 'javax.swing.JTable'
java_import 'javax.swing.table.DefaultTableModel'
java_import 'javax.swing.DefaultListModel'
java_import 'javax.swing.JPanel'
java_import 'javax.swing.JTabbedPane'
java_import 'javax.swing.JButton'
java_import 'javax.swing.JScrollBar'
java_import 'javax.swing.JOptionPane'
java_import 'javax.swing.JCheckBox'
java_import 'javax.swing.JRadioButton'
java_import 'javax.swing.ButtonGroup'
java_import 'javax.swing.JTextField'
java_import 'javax.swing.JTextArea'
java_import 'javax.swing.JLabel'
java_import 'javax.swing.JFileChooser'
java_import 'javax.swing.filechooser.FileFilter'
java_import 'javax.swing.JList'
java_import 'javax.swing.JScrollPane'
java_import 'javax.swing.Box'
java_import 'javax.swing.BoxLayout'
java_import 'javax.swing.SwingConstants'
java_import 'javax.swing.BorderFactory'
java_import 'javax.swing.GroupLayout'
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
java_import 'burp.IIntruderAttack'
java_import 'burp.IIntruderPayloadGenerator'
java_import 'burp.IIntruderPayloadGeneratorFactory'
java_import 'burp.IIntruderPayloadProcessor'
java_import 'burp.IProxyListener'
java_import 'burp.IInterceptedProxyMessage'

## TODO: Add scan status to Result page
class BurpExtender
  include IBurpExtender, IExtensionHelpers
  include IHttpService, IHttpListener, IHttpRequestResponse
  include IIntruderAttack, IIntruderPayloadGenerator, IIntruderPayloadGeneratorFactory, IIntruderPayloadProcessor
  include IProxyListener, IInterceptedProxyMessage
  include ITab, IMenuItemHandler
  
  
  def registerExtenderCallbacks(_burp)
    @started = false
    @threads = []
    @n_threads = 0
    @status = nil
    @x_payloads = []
    @x_wordlist = []
    @x_result = []
    @intruder = nil
        
    # init
    @burp = _burp
    @burp.setExtensionName("What the WAF?!")
    @helpers = @burp.getHelpers()
    @burp.registerIntruderPayloadGeneratorFactory(self)
    @burp.registerIntruderPayloadProcessor(self)
    @burp.registerProxyListener(self)
    
    # gui
    # # tabs
    @tabs = JTabbedPane.new()
    
    initTargetUI
    initResultUI
    initPayloads

    @burp.customizeUiComponent(@tabs)
    @burp.addSuiteTab(self)
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
    
    # # INFO PANEL # #
    @pan_info = JPanel.new()
    @lay_info = GroupLayout.new(@pan_info)
    @lay_info.setAutoCreateGaps(true)
    @lay_info.setAutoCreateContainerGaps(true)
    @pan_info.setLayout(@lay_info)
    @pan_info.setBorder(BorderFactory.createMatteBorder(0,0,2,0, Color.orange))
    lbl_head = JLabel.new("<html><h3>How to use</h3></html>")
    lbl_body = JLabel.new("<html><p>1. This extension works beside the Intruder, so send your target request to the Intruder and select your parameters as you always do.<br>2. Under the \"Payloads\" tab select the \"Payload type\" to <b>\"Extension-generated\"</b><br>3. Under the \"Payload Options\" section, click on the \"select generator\" button and choose \"What the WAF?!\".<br>4. Under the \"Payload Processing\" click \"add\" then select <b>\"Invoke Burp Extension\"</b> and choose \"What The WAF?!\" as your processor.<br>5. Start Attack.</p><b>Important Notes:</b><br><p>1. Current version does not support simultaneous attacks.<br>2. Scan one parameter at a time (Sniper mode)</p></html>")
    txt_shit = JTextField.new()
    
    @lay_info.setHorizontalGroup(
      @lay_info.createParallelGroup(GroupLayout::Alignment::LEADING
        ).addComponent(lbl_head
        ).addComponent(lbl_body)
    )
    
    @lay_info.setVerticalGroup(
      @lay_info.createSequentialGroup(
        ).addComponent(lbl_head
        ).addComponent(lbl_body)
    )
    
    # # WAF PANEL # #
    @pan_waf = JPanel.new()
    @lay_waf = GroupLayout.new(@pan_waf)
    @lay_waf.setAutoCreateGaps(true)
    @lay_waf.setAutoCreateContainerGaps(true)
    @pan_waf.setLayout(@lay_waf)
    @pan_waf.setBorder(BorderFactory.createMatteBorder(0,0,2,0, Color.orange))
    lbl_waf = JLabel.new("<html><h3>WAF Options</h3></html>")
    
    lbl_hcode = JLabel.new("<html><b>WAF HTTP Response CODE</b><br><i>HTTP response code(s) used by WAF to block malicious requests</i></html>")
    @chk = {}
    @chk["200"] = JCheckBox.new("<html>200: OK (WAF was configured to show a <i>\"block\" page</i> <b>directly</b>)</html>")
    @chk["301"] = JCheckBox.new("301: Moved Permanently")
    @chk["302"] = JCheckBox.new("302: Found")
    @chk["400"] = JCheckBox.new("400: Bad Request")
    @chk["401"] = JCheckBox.new("401: Unauthorized")
    @chk["403"] = JCheckBox.new("403: Forbidden")
    @chk["404"] = JCheckBox.new("404: Not Found")
    @chk["500"] = JCheckBox.new("500: Internal Server Error")
    @chk["502"] = JCheckBox.new("502: Bad Gateway")
    @chk["503"] = JCheckBox.new("503: Service Unavailable")
    @chk["504"] = JCheckBox.new("504: Gateway Timeout")
    pan_code = JPanel.new()
    pan_code.setLayout(GridLayout.new(0,3))
    @chk.each do |n,c|
      pan_code.add(c)
    end
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
        ).addComponent(pan_code
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
        ).addComponent(pan_code
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
    @lay_pay.setAutoCreateGaps(true)
    @lay_pay.setAutoCreateContainerGaps(true)
    @pan_pay.setLayout(@lay_pay)
    @pan_pay.setBorder(BorderFactory.createMatteBorder(0,0,2,0, Color.orange))
    lbl_pay = JLabel.new("<html><h3>Payload Options</h3></html>")
    lbl_sel = JLabel.new("<html><b>Wordlist</b><br><i>Note: Selected wordlist files will be reloaded, each time you start the attack\"<br>Multi-selection was enabled</i></html>")
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
    @lay_scan.setAutoCreateGaps(true)
    @lay_scan.setAutoCreateContainerGaps(true)
    @pan_scan.setLayout(@lay_scan)
    @pan_scan.setBorder(BorderFactory.createMatteBorder(0,0,2,0, Color.orange))
    lbl_scan = JLabel.new("<html><h3>Scan Options</h3></html>")
    @chk_encode = JCheckBox.new("Force url encoding")
    lbl_scan_ses = JLabel.new("<html><b>Session Settings</b></html>")
    lbl_delay = JLabel.new("Delay")
    lbl_scan_cont = JLabel.new("<html><br><b>Content Settings</b></html>")
    @txt_delay = JTextField.new("0")
    lbl_threads = JLabel.new("Threads")
    @txt_threads = JTextField.new("4")
    
    @lay_scan.setHorizontalGroup(
      @lay_scan.createParallelGroup(GroupLayout::Alignment::LEADING
        ).addComponent(lbl_scan
        ).addComponent(lbl_scan_ses
        ).addGroup(@lay_scan.createSequentialGroup(
          ).addComponent(lbl_delay
          ).addComponent(@txt_delay, 100, 100, 100)
        ).addGroup(@lay_scan.createSequentialGroup(
          ).addComponent(lbl_threads
          ).addComponent(@txt_threads, 100, 100, 100)
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
        ).addGroup(@lay_scan.createParallelGroup(GroupLayout::Alignment::BASELINE
          ).addComponent(lbl_threads
          ).addComponent(@txt_threads)
        ).addComponent(lbl_scan_cont
        ).addComponent(@chk_encode)
    )
    
    # Finalize layout
    @lay_tgt.setHorizontalGroup(
      @lay_tgt.createParallelGroup(GroupLayout::Alignment::LEADING
        ).addComponent(@pan_info
        ).addComponent(@pan_waf
        ).addComponent(@pan_pay
        ).addComponent(@pan_scan)
    )
    
    @lay_tgt.setVerticalGroup(
      @lay_tgt.createSequentialGroup(
        ).addComponent(@pan_info
        ).addComponent(@pan_waf
        ).addComponent(@pan_pay
        ).addComponent(@pan_scan)
    )
    
    # Add Action Listeners
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
    @lbl_stat = JLabel.new("Status: Stopped")
    
    @lay_res.setHorizontalGroup(
      @lay_res.createParallelGroup(GroupLayout::Alignment::LEADING
        ).addComponent(lbl_passed
        ).addComponent(scroll_tbl
        ).addComponent(@lbl_stat)
    )
    
    @lay_res.setVerticalGroup(
      @lay_res.createSequentialGroup(
        ).addComponent(lbl_passed
        ).addComponent(scroll_tbl
        ).addComponent(@lbl_stat)
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
  
  def loadEmAll
    # JOptionPane.showMessageDialog(nil, "Loading ...")
    @n_threads = @txt_threads.getText().to_s.to_i
    # @baseline = @txt_req.getText().to_s
    @force_encoding = @chk_encode.isSelected()
    @delay = @txt_delay.getText().to_s.to_i
    @add_prefix = @rdo_pat_left.isSelected()
    @add_suffix = @rdo_pat_right.isSelected()
    @add_both = @rdo_pat_both.isSelected()
    @pattern = @txt_pay_pat.getText()
    @max_size = @txt_max_pay_size.getText().to_s.to_i
    @min_size = @txt_min_pay_size.getText().to_s.to_i
    
    # JOptionPane.showMessageDialog(nil, "Half Done ...")
    @all_payloads = []
    @all_wordlists = []
    @n_payloads = 0
    
    @tbl_res_model.setRowCount(0)
    cell = @lst_pay.getSelectedValues()
    @wordlist.each do |k,v|
      next unless cell.
      # JOptionPane.showMessageDialog(nil, k + " - " + v)
      File.open(v).each do |l|
        l = l.chomp
        next if l.empty?
        @all_payloads[@n_payloads] = l
        @all_wordlists[@n_payloads] = k
        
        # JOptionPane.showMessageDialog(nil, l)
        # @tbl_res_model.addRow([@n_payloads, @all_wordlists[@n_payloads], @all_payloads[@n_payloads]].to_java)
        @n_payloads = @n_payloads + 1
      end
    end
    
    @timeout = @txt_timeout.getText().to_s.to_i
    @block_page = @txt_block_url.getText().to_s.to_i
    @response = {}
    @chk.each do |c,b|
      @response[c] = @chk[c].isSelected()
    end
    @param = @txt_param.getText
    # JOptionPane.showMessageDialog(nil, "All Done")
  end
  
  # ------------------------------ THE BURP PART OF THINGS ------------------------------ #
  # String ITab::getTabCaption();
  def getTabCaption
    return "What the WAF?!"
  end
  
  # Component ITab::getUiComponent();
  def getUiComponent
    return @tabs
  end

  # IIntruderPayloadGenerator IIntruderPayloadGeneratorFactory::createNewInstance(IIntruderAttack attack);
  def createNewInstance(attack)
    @intruder = attack
    self
  end
  
  # String IIntruderPayloadGeneratorFactory::getGeneratorName();
  def getGeneratorName
    "What The WAF?!"
  end
  
  # boolean IIntruderPayloadGenerator::hasMorePayloads();
  def hasMorePayloads
    ## TODO
    false
  end
  
  # byte[] IIntruderPayloadGenerator::getNextPayload(byte[] baseValue);
  def getNextPayload(baseValue)
    ## TODO
    nil
  end
  
  # void IIntruderPayloadGenerator::reset();
  def reset()
    ## TODO
  end
  
  # String IIntruderPayloadProcessor::getProcessorName();
  def getProcessorName
    "What The WAF?!"
  end
  
  # public byte[] IIntruderPayloadProcessor::processPayload(byte[] currentPayload, byte[] originalPayload, byte[] baseValue)
  def processPayload(currentPayload, originalPayload, baseValue)
    ## TODO
    nil
  end
  
  #  void IProxyListener::processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message);
  def processProxyMessage(messageIsRequest, message)
    ## TODO
  end
end
