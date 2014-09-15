# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
# What the WAF?! extension for burp                                                     #
#                                                                                       #
# by _null_                                                                             #
# source code (GPLv3) is available at github: https://github.com/null--/what-the-waf    #
#                                                                                       #
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
require 'java'

# The long list of JAVA/JAVAX imports!
java_import java.awt.Color
java_import java.awt.Dimension
java_import java.awt.event.ActionListener
java_import java.awt.BorderLayout
java_import java.awt.FlowLayout
java_import java.awt.GridLayout
java_import java.awt.Container
java_import java.awt.event.MouseAdapter
java_import javax.swing.JTable
java_import javax.swing.JPopupMenu
java_import javax.swing.JMenuItem
java_import javax.swing.table.DefaultTableModel
java_import javax.swing.DefaultListModel
java_import javax.swing.JPanel
java_import javax.swing.JTabbedPane
java_import javax.swing.JButton
java_import javax.swing.JScrollBar
java_import javax.swing.JOptionPane
java_import javax.swing.JCheckBox
java_import javax.swing.JRadioButton
java_import javax.swing.ButtonGroup
java_import javax.swing.JTextField
java_import javax.swing.JTextArea
java_import javax.swing.JLabel
java_import javax.swing.JFileChooser
java_import javax.swing.filechooser.FileFilter
java_import javax.swing.JList
java_import javax.swing.ListSelectionModel
java_import javax.swing.JScrollPane
java_import javax.swing.Box
java_import javax.swing.BoxLayout
java_import javax.swing.SwingConstants
java_import javax.swing.SwingUtilities
java_import javax.swing.BorderFactory
java_import javax.swing.GroupLayout
java_import javax.swing.border.LineBorder
java_import javax.swing.border.EmptyBorder
java_import javax.swing.border.TitledBorder

# BURP imports
java_import 'burp.IBurpExtender'
java_import 'burp.IHttpListener'
java_import 'burp.IExtensionStateListener'
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

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
# -------------------------------- READ ONLY TABLE MODEL ------------------------------ #
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
class ReadOnlyTableModel < DefaultTableModel
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
  def isCellEditable(r, c)
    false
  end
end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
# ------------------- RESULTS TABLE MOUSE RCLICK HANDLER ------------------------------ #
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
class ResultMouse < MouseAdapter
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
  attr_accessor :parent

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def initialize()
    super
    
    @popup = JPopupMenu.new()
    @mnu_send_to_rep = JMenuItem.new("Send to repeater")
    @popup.add( @mnu_send_to_rep )
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def createMenu(_parent)
    @parent = _parent
    @mnu_send_to_rep.addActionListener do |e|
      @parent.popupSendtoRepeater(e)
    end
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def mousePressed(e)
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def mouseReleased(e)
    return if @parent.tbl_res.getSelectedRow() < 0
    
    if SwingUtilities.isRightMouseButton(e) then
      @popup.show(e.getComponent(), e.getX(), e.getY())
    end
  end
end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
# ------------------------------ PAYLOAD GENERATOR ------------------------------------ #
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
class PayGen
  include IIntruderPayloadGenerator
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  attr_accessor :cur_pos
  attr_accessor :n_payloads
  attr_accessor :all_payloads
  attr_accessor :parent

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def initialize(_p, _pp)
    @parent = _p
    @all_payloads = _pp
    @cur_pos = 0
    @n_payloads = @all_payloads.size
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  # boolean IIntruderPayloadGenerator::hasMorePayloads();
  def hasMorePayloads
    return (@cur_pos < @n_payloads)
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  # byte[] IIntruderPayloadGenerator::getNextPayload(byte[] baseValue);
  def getNextPayload(baseValue)
    @cur_pos = @cur_pos + 1
    return @all_payloads[@cur_pos - 1].to_java_bytes
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  # void IIntruderPayloadGenerator::reset();
  def reset()
    @cur_pos = 0
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def lastPos
    @cur_pos - 1
  end
end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
# ------------------------------ EXTENSION CLASS -------------------------------------- #
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
class BurpExtender
  include IBurpExtender, IExtensionStateListener
  include IHttpListener
  include IIntruderAttack, IIntruderPayloadGeneratorFactory, IIntruderPayloadProcessor
  include ITab

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  attr_accessor :tbl_res
  attr_accessor :tbl_res_model
  attr_accessor :all_result
  attr_accessor :all_response

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
  def registerExtenderCallbacks(_burp)
    @started = false
    @status = nil
    @all_result = []
    @all_response = []
    @intruder = nil
    
    # init
    @burp = _burp
    @burp.setExtensionName("What the WAF?!")
    @helper = @burp.getHelpers()
    
    @burp.registerIntruderPayloadGeneratorFactory(self)
    @burp.registerIntruderPayloadProcessor(self)
    @burp.registerHttpListener(self)
    @burp.registerExtensionStateListener(self)
    
    # gui
    # # tabs
    @tabs = JTabbedPane.new()
    
    initTargetUI
    initResultUI
    initPayloads

    @burp.customizeUiComponent(@tabs)
    @burp.addSuiteTab(self)
    
    @total_index = 0    
    # loadEmAll
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
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
    lbl_head = JLabel.new("<html><h3>README</h3></html>")
    lbl_body = JLabel.new("<html><p>1. This extension works beside the Intruder, so send your target request to the Intruder and select your parameters as you always do.<br>2. Under the \"Payloads\" tab select the \"Payload type\" to <b>\"Extension-generated\"</b><br>3. Under the \"Payload Options\" section, click on the \"select generator\" button and choose \"What the WAF?!\".<br>4. Under the \"Payload Processing\" click \"add\" then select <b>\"Invoke Burp Extension\"</b> and choose \"What The WAF?!\" as your processor.<br>5. Start Attack.</p><br><p>Note:<br>1.On the \"Resuls\" tab you can select a row then right-click on it and choose \"Send to repeater\"</p><b>Important Notes:</b><br><p>1. Current version does not support simultaneous attacks.<br>2. Scan one parameter at a time (Sniper mode)</p></html>")
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
    lbl_pay_size = JLabel.new("Payload size")
    @txt_pay_size = JTextField.new("512")
    lbl_pay_size_info = JLabel.new("<html><i>'0' means: Do not add patter<br></i></html>")
    lbl_pay_pat = JLabel.new("Pattern")
    @txt_pay_pat = JTextField.new("%20")
    lbl_pay_pat_info = JLabel.new("<html><i>If the payload length be less than the \"Minimum payload size\", this pattern will be used to increase the size of payload.<br></i></html>")
    lbl_pat_grp = JLabel.new("<html><br><b>Prefix/Suffix</b></html>")
    @rdo_pat_left = JRadioButton.new("Treat the pattern as prefix")
    @rdo_pat_right = JRadioButton.new("Treat the pattern as suffix")
    @rdo_pat_both = JRadioButton.new("Both!", true)
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
          ).addComponent(lbl_pay_size
          ).addComponent(@txt_pay_size, 100, 100, 100)
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
          ).addComponent(lbl_pay_size
          ).addComponent(@txt_pay_size)
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
    @chk_encode = JCheckBox.new("Force url encoding", true)
    lbl_scan_cont = JLabel.new("<html><br><b>Content Settings</b></html>")
    @txt_delay = JTextField.new("0")
    
    @lay_scan.setHorizontalGroup(
      @lay_scan.createParallelGroup(GroupLayout::Alignment::LEADING
        ).addComponent(lbl_scan
        ).addComponent(lbl_scan_cont
        ).addComponent(@chk_encode)
    )
    
    @lay_scan.setVerticalGroup(
      @lay_scan.createSequentialGroup(
        ).addComponent(lbl_scan
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
      addPayload(e)
    end
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
  def initResultUI
    container = JPanel.new()
    @tab_pl  = @tabs.addTab("Result", container)
    
    container.setLayout(BorderLayout.new())
    container.setBorder(EmptyBorder.new( 3, 3, 3, 3 ) )
    @pan_res = JPanel.new()
    @lay_res = GroupLayout.new(@pan_res)
    @pan_res.setLayout(@lay_res)
    container.add(@pan_res, BorderLayout::CENTER)
    
    lbl_passed = JLabel.new("<html><u>Below, is a list of <b>passed</b> payloads.</u><br><i>You can select a row then press Ctrl+C to copy its content or right-click on it and choose \"Send to repeater\"</i></html>")
    @tbl_res_model = ReadOnlyTableModel.new()
    @tbl_res_model.addColumn("#")
    @tbl_res_model.addColumn("Wordlist")
    @tbl_res_model.addColumn("Payload")
    @tbl_res_model.addColumn("HTTP Request")
    @tbl_res = JTable.new(@tbl_res_model)
    scroll_tbl = JScrollPane.new(@tbl_res)
    @tbl_res.setFillsViewportHeight(true);
    @tbl_res.setSelectionMode(ListSelectionModel::SINGLE_SELECTION)
    @tbl_res.getColumnModel().getColumn(0).setPreferredWidth(50)
    @tbl_res.getColumnModel().getColumn(1).setPreferredWidth(100)
    @tbl_res.getColumnModel().getColumn(2).setPreferredWidth(300)
    @tbl_res.getColumnModel().getColumn(3).setPreferredWidth(500)
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
    
    @mouse_handler = ResultMouse.new
    @mouse_handler.createMenu(self)
    @tbl_res.addMouseListener( @mouse_handler )
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def popupSendtoRepeater(e)
    row = @tbl_res.getSelectedRow
    # JOptionPane.showMessageDialog(nil, @all_response[row].getHttpService().getHost().to_s + ":" + @all_response[row].getHttpService.getPort.to_s + "\n" + @all_response[row].getRequest().to_s)
    
    @burp.sendToRepeater(
      @all_response[row].getHttpService().getHost, 
      @all_response[row].getHttpService().getPort, 
      @all_response[row].getHttpService().getProtocol() == "https", 
      @all_response[row].getRequest(),
      ("What the WAF?! #" + (row+1).to_s).to_java_string 
    )
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def initPayloads
    paydir = File.expand_path(File.dirname(__FILE__)) + "/payloads/"
    @wordlist = {}
    Dir.glob(paydir+ "*.lst") do |p|
      #JOptionPane.showMessageDialog(nil, p)
      #if File.extname(p) == ".lst" then
        @wordlist[File.basename(p, ".*")] = p
        @lst_pay_model.addElement(File.basename(p, ".*"))
      #end
    end
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def addPayload(e)
    fc = JFileChooser.new()
    fc.setFileFilter(WordlistFilter.new())
    if fc.showOpenDialog(@tabs) == JFileChooser::APPROVE_OPTION then
      p = fc.getSelectedFile().to_s
      # TODO: Check for duplicates
      @wordlist[File.basename(p, ".*")] = p
      @lst_pay_model.addElement(File.basename(p, ".*"))
    end
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def loadEmAll
    @force_encoding = @chk_encode.isSelected()
    @delay = @txt_delay.getText().to_s.to_i
    @add_prefix = @rdo_pat_left.isSelected()
    @add_suffix = @rdo_pat_right.isSelected()
    @add_both = @rdo_pat_both.isSelected()
    if @add_both then
      @add_prefix = true
      @add_suffix = true
    end
    @pattern = @txt_pay_pat.getText()
    @pay_size = @txt_pay_size.getText().to_s.to_i
    
    # JOptionPane.showMessageDialog(nil, "Half Done ...")
    @all_payloads = []
    @all_wordlists = []
    @n_payloads = 0
    
    @tbl_res_model.setRowCount(0)
    # cell = @lst_pay.getSelectedValues()
    @wordlist.each do |k,v|
      ## TODO: Multi selection
      # next unless cell.find(k)
      # JOptionPane.showMessageDialog(nil, k + " - " + v)
      File.open(v).each do |l|
        l = l.chomp
        next if l.empty?
        @all_payloads[@n_payloads] = l
        @all_wordlists[@n_payloads] = k
        @n_payloads = @n_payloads + 1
      end
    end
    @all_result = Array.new(@n_payloads, false)
    
    @timeout = @txt_timeout.getText().to_s.to_i
    @block_page = @txt_block_url.getText().to_s.to_i
    @response = {}
    @chk.each do |c,b|
      @response[c] = @chk[c].isSelected()
    end
    
    @cur_pos = 0
  end
  
  def addResult(w, p, r)
    @total_index = @total_index + 1
    @tbl_res_model.addRow([@total_index, w, p, r].to_java)
  end
  
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
# -------------------------------------- BURP HOOKS ----------------------------------- #
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
  # String ITab::getTabCaption();
  def getTabCaption
    "What the WAF?!"
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
  # String IIntruderPayloadGeneratorFactory::getGeneratorName();
  def getGeneratorName
    "What The WAF?!"
  end
  
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  # Component ITab::getUiComponent();
  def getUiComponent
    @tabs
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
  # IIntruderPayloadGenerator IIntruderPayloadGeneratorFactory::createNewInstance(
  #   IIntruderAttack attack);
  def createNewInstance(attack)
    @intruder = attack
    loadEmAll
    # JOptionPane.showMessageDialog(nil, "New instance")
    @pg = PayGen.new(self, @all_payloads)
    return @pg
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  # String IIntruderPayloadProcessor::getProcessorName();
  def getProcessorName
    "What The WAF?!"
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  # public byte[] IIntruderPayloadProcessor::processPayload(
  #   byte[] currentPayload,
  #   byte[] originalPayload, 
  #   byte[] baseValue)
  def processPayload(currentPayload, originalPayload, baseValue)
    ## TODO: Processed payload size does not match the exact @pay_size value
    
    if @force_encoding then
      currentPayload = @helper.urlEncode(currentPayload)
    end
    
    cs = currentPayload.to_s
    if @pay_size > 0 and @pattern != "" then
      if cs.size > @pay_size then
        cs = cs[0..@pay_size]
      else
        ps = @pattern.size
        
        rem = @pay_size - cs.size
        lrem = rrem = rem
        if @add_both then
          lrem = rrem = rem/2
        end
        
        if @add_prefix then
          q = lrem / ps
          cs = (@pattern * q) + cs
        end
        
        if @add_suffix then
          q = rrem / ps
          cs = cs + (@pattern * q)
        end
      end
    end
    
    return cs.to_java_bytes
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  # void IHttpListener::processHttpMessage(
  #   int toolFlag, 
  #   boolean messageIsRequest, 
  #   IHttpRequestResponse messageInfo);
  def processHttpMessage(toolFlag, messageIsRequest, messageInfo)
    return unless toolFlag == 0x20 # DUMMY!
    return if messageInfo.getComment().to_s.downcase.include?("baseline")
    
    ## TODO
    if not messageIsRequest and not @pg.nil? then
      # JOptionPane.showMessageDialog(nil, "RECV \n" + messageInfo.getResponse().to_s)
      @all_response[ @total_index ] = messageInfo
      addResult(@all_wordlists[ @pg.lastPos ], @all_payloads[ @pg.lastPos ], @all_response[ @total_index ].getRequest().to_s)
    end
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  # void extensionUnloaded();
  def extensionUnloaded
    ## TODO
  end
end

