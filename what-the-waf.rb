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
java_import javax.swing.table.DefaultTableCellRenderer
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
java_import 'burp.ISessionHandlingAction'

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
VERSION         = "0.15 (alpha)"
WTW_ACT_NAME    = "What the WAF?!"
WTW_GEN_NAME    = "What the WAF?!"
WTW_PRC_NAME    = "What The WAF?!"
WTW_TAB_CAPTOIN = "What the WAF?!"
TIMEOUT_TRESH   = 5

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
def random(len)
  (0...len).map { ('a'..'z').to_a[rand(26)] }.join
end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
# ------------------------------ WORDLIST FILTER -------------------------------------- #
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
class WordlistFilter < FileFilter
  def accept(f)
    return true unless File.file?(f.to_s)
    
    return true if File.extname(f.to_s) == ".txt"
    return true if File.extname(f.to_s) == ".lsd"
    
    return false
  end
  
  def getDescription
    "Line-seperated Wordlist Files (*.txt or *.lsd)"
  end
end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
# --------------------------------- MY TABLE MODEL ------------------------------------ #
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
class MyTableModel < DefaultTableModel
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
  def isCellEditable(r, c)
    false
  end
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def getColumnClass(col)
    case col
    when 1
      return java.lang.Boolean
    else
      return java.lang.String
    end
  end
end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
# -------------------------------- MY TABLE RENDERER ---------------------------------- #
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
class MyTableRenderer < DefaultTableCellRenderer
  def getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col)
    # c = DefaultTableCellRenderer.instance_method(
    #   getTableCellRendererComponent).bind(self).call(
    #     table, value, isSelected, hasFocus, row, col)
    
    c = super(table, value, isSelected, hasFocus, row, col)
    
    if table.getModel().getValueAt(row, 1) then
      c.setBackground( Color.new(253,90,100) )
    else
      c.setBackground( Color.new(144,253,169) )
    end
    return c
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
  attr_accessor :allow
  
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def initialize(_p)
    @parent = _p
    reset
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  # boolean IIntruderPayloadGenerator::hasMorePayloads();
  def hasMorePayloads
    return (@cur_pos < @n_payloads)
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  # byte[] IIntruderPayloadGenerator::getNextPayload(byte[] baseValue);
  def getNextPayload(baseValue)    
    while not @allow[@cur_pos] do
      # JOptionPane.showMessageDialog(nil, "Not allowed: " + @cur_pos.to_s + ": " + @allow[@cur_pos].to_s)
      # @parent.stdout.println("Stucked for " + (@cur_pos).to_s)
      sleep(0.1)
    end
    
    @parent.all_timestamp[ @cur_pos ] = Time.now.to_i
    @parent.all_sent[ @cur_pos ] = random(8)
    
    @cur_pos = @cur_pos + 1
    return @all_payloads[@cur_pos - 1].to_java_bytes
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  # void IIntruderPayloadGenerator::reset();
  def reset
    @cur_pos = 0
    @parent.loadEmAll
    
    @all_payloads = @parent.all_payloads
    @n_payloads = @all_payloads.size
    
    @allow = Array.new(@n_payloads, false)
    @allow[0] = true
    @allow[1] = true
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def lastPos
    @cur_pos - 1
  end
  
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def allowNext
    # @parent.stdout.println("Allowing " + (@cur_pos+1).to_s)
    @allow[@cur_pos] = true
  end
end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
# ------------------------------ EXTENSION CLASS -------------------------------------- #
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
class BurpExtender
  include IBurpExtender, IExtensionStateListener, ISessionHandlingAction
  include IHttpListener
  include IIntruderAttack, IIntruderPayloadGeneratorFactory, IIntruderPayloadProcessor
  include ITab

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  attr_accessor :tbl_res
  attr_accessor :tbl_res_model
  attr_accessor :all_payloads
  attr_accessor :all_result
  attr_accessor :all_response
  attr_accessor :all_timestamp
  attr_accessor :all_sent
  attr_accessor :all_processed
  attr_accessor :stdout
  attr_accessor :stderr
  
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
  def registerExtenderCallbacks(_burp)
    @all_sent = []
    @all_processed = []
    
    @started = false
    @status = nil
    @all_result = []
    @all_response = []
    @all_timestamp = []
    @intruder = nil
    
    # init
    @burp = _burp
    @burp.setExtensionName("What the WAF?!")
    @helper = @burp.getHelpers()
    
    @burp.registerSessionHandlingAction(self)
    @burp.registerIntruderPayloadGeneratorFactory(self)
    @burp.registerIntruderPayloadProcessor(self)
    @burp.registerHttpListener(self)
    @burp.registerExtensionStateListener(self)
    @stdout = java.io.PrintWriter.new(@burp.getStdout(), true)
    @stderr = java.io.PrintWriter.new(@burp.getStderr(), true)
    
    # gui
    # # tabs
    @tabs = JTabbedPane.new()
    
    initTargetUI
    initResultUI
    initReadmeUI
    
    initPayloads

    @burp.customizeUiComponent(@tabs)
    @burp.addSuiteTab(self)
    
    @total_index = 0    
    # loadEmAll
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
  def initReadmeUI
    container = JPanel.new()
    @tab_rme = @tabs.addTab("Readme", container)
    
    container.setLayout(BorderLayout.new())
    container.setBorder(EmptyBorder.new( 3, 3, 3, 3 ) )
    @pan_rme = JPanel.new()
    @lay_rme = GroupLayout.new(@pan_rme)
    @pan_rme.setLayout(@lay_rme)
    scroll = JScrollPane.new(@pan_rme)
    container.add(scroll, BorderLayout::CENTER)
    
    # # INFO PANEL # #
    @pan_info = JPanel.new()
    @lay_info = GroupLayout.new(@pan_info)
    @lay_info.setAutoCreateGaps(true)
    @lay_info.setAutoCreateContainerGaps(true)
    @pan_info.setLayout(@lay_info)
    @pan_info.setBorder(BorderFactory.createMatteBorder(0,0,2,0, Color.orange))
    
    lbl_head = JLabel.new("<html><h3>README</h3></html>")
    lbl_body = JLabel.new("<html><h4>About</h4><p>by _null_ (Sina Hatef)<br>Project Link: <a href=\"https://github.com/null--/what-the-waf\">https://github.com/null--/what-the-waf</a></p><p><h4>How to use</h4>1. This extension works beside the Intruder, so send your target request to the Intruder and select your parameters as you always do.<br>2. Under the \"Payloads\" tab select the \"Payload type\" to <b>\"Extension-generated\"</b><br>3. Under the \"Payload Options\" section, click on the \"select generator\" button and choose \"What the WAF?!\".<br>4. Under the \"Payload Processing\" click \"add\" then select <b>\"Invoke Burp Extension\"</b> and choose \"What The WAF?!\" as your processor.<br>5. Start Attack.</p><p><h4>Note</h4>1.On the \"Resuls\" tab you can select a row then right-click on it and choose \"Send to repeater\"</p><h4>Important Notes</h4><p>1. Current version does not support simultaneous Intruder attacks.<br>2. Scan one parameter at a time (Sniper mode)</p></html>")
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
    
    @lay_rme.setHorizontalGroup(
      @lay_rme.createParallelGroup(GroupLayout::Alignment::LEADING
        ).addComponent(@pan_info)
    )
    
    @lay_rme.setVerticalGroup(
      @lay_rme.createSequentialGroup(
        ).addComponent(@pan_info)
    )
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
    @chk["302"] = JCheckBox.new("302: Found", true)
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
    lbl_red = JLabel.new("<html><b>WAF Block/Redirection URL</b><br><i>After being detected, Where does WAF redirect you?</i></html>")
    lbl_block_url = JLabel.new("Block/Redirection URL (the \"Location\" Header Field)")
    @txt_block_url = JTextField.new()
    lbl_timeout = JLabel.new("Block timeout (seconds)")
    @txt_timeout = JTextField.new()
    lbl_timeout_info = JLabel.new("<html><i>The connection timeout value used by WAF to block a malicious client.</i><b> (EXPERIMENTAL)</b></html>")
    lbl_body = JLabel.new("Search inside body (REGEX)")
    @txt_body = JTextField.new()
    lbl_len = JLabel.new("Length: ")
    @txt_len = JTextField.new("0")
    lbl_len_info = JLabel.new("<html><i>In case of pentesting mod_security or Fortiweb this option setting this option will become very useful<br>Please, notice that if you set length to be 0 then this will ignore checking response size.</i></html>")
    
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
        ).addComponent(lbl_timeout_info
        ).addGroup(@lay_waf.createSequentialGroup(
          ).addComponent(lbl_body
          ).addComponent(@txt_body, 300, 500, 600)
        ).addGroup(@lay_waf.createSequentialGroup(
          ).addComponent(lbl_len
          ).addComponent(@txt_len, 100, 100, 100)
        ).addComponent(lbl_len_info)
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
        ).addComponent(lbl_timeout_info
        ).addGroup(@lay_waf.createParallelGroup(GroupLayout::Alignment::BASELINE
          ).addComponent(lbl_body
          ).addComponent(@txt_body)
        ).addGroup(@lay_waf.createParallelGroup(GroupLayout::Alignment::BASELINE
          ).addComponent(lbl_len
          ).addComponent(@txt_len)
        ).addComponent(lbl_len_info)
    )
    
    # # PAYLOAD PANEL # #
    @pan_pay = JPanel.new()
    @lay_pay = GroupLayout.new(@pan_pay)
    @lay_pay.setAutoCreateGaps(true)
    @lay_pay.setAutoCreateContainerGaps(true)
    @pan_pay.setLayout(@lay_pay)
    @pan_pay.setBorder(BorderFactory.createMatteBorder(0,0,2,0, Color.orange))
    lbl_pay = JLabel.new("<html><h3>Payload Options</h3></html>")
    lbl_sel = JLabel.new("<html><b>Wordlist</b><br><i>Note: Selected wordlist files will be reloaded, each time you start the attack\"</i></html>")
    @lst_pay_model = DefaultListModel.new()
    @lst_pay = JList.new(@lst_pay_model)
    @lst_pay.setSelectionMode(ListSelectionModel::SINGLE_SELECTION)
    @lst_pay_scr = JScrollPane.new(@lst_pay)
    lbl_pay_add = JLabel.new("<html><i>Add new wordlist (line-seperated list of paylaods)</i></html>")
    @btn_pay_add = JButton.new("Add")
    @btn_pay_rem = JButton.new("Remove")
    @btn_pay_cls = JButton.new("Clear")
    @btn_pay_def = JButton.new("Default")
    lbl_cont = JLabel.new("<html><br><b>Payload Factory</b></html>")
    lbl_pay_size = JLabel.new("Payload size")
    @txt_pay_size = JTextField.new("0")
    lbl_pay_size_info = JLabel.new("<html><i>'0' means: Do not add pattern<br></i></html>")
    lbl_pay_pat = JLabel.new("Pattern")
    @txt_pay_pat = JTextField.new("")
    lbl_pay_pat_info = JLabel.new("<html><i>If the payload length be less than the \"Minimum payload size\", this pattern will be used to increase the size of payload.<br></i></html>")
    lbl_pat_grp = JLabel.new("<html><br><b>Prefix/Suffix</b></html>")
    @rdo_pat_left = JRadioButton.new("Treat the pattern as prefix")
    @rdo_pat_right = JRadioButton.new("Treat the pattern as suffix", true)
    @rdo_pat_both = JRadioButton.new("Both!")
    grp_pat = ButtonGroup.new()
    grp_pat.add(@rdo_pat_left)
    grp_pat.add(@rdo_pat_right)
    grp_pat.add(@rdo_pat_both)
    
    @lay_pay.setHorizontalGroup(
      @lay_pay.createParallelGroup(GroupLayout::Alignment::LEADING
        ).addComponent(lbl_pay
        ).addComponent(lbl_sel
        ).addComponent(@lst_pay_scr, 450, 450, 450
        ).addComponent(lbl_pay_add
        ).addGroup(@lay_pay.createSequentialGroup(
          ).addComponent(@btn_pay_add
          ).addComponent(@btn_pay_rem
          ).addComponent(@btn_pay_cls
          ).addComponent(@btn_pay_def)
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
        ).addComponent(@lst_pay_scr, 400, 400, 400
        ).addComponent(lbl_pay_add
        ).addGroup(@lay_pay.createParallelGroup(GroupLayout::Alignment::BASELINE
          ).addComponent(@btn_pay_add
          ).addComponent(@btn_pay_rem
          ).addComponent(@btn_pay_cls
          ).addComponent(@btn_pay_def)
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
    @chk_encode = JCheckBox.new("Apply URL-encoding on payloads", false)
    lbl_scan_cont = JLabel.new("<html><b>Content Settings</b></html>")
    @txt_delay = JTextField.new("0")
    lbl_res_grp = JLabel.new("<html><b>Results</b></html>")
    @rdo_blocked = JRadioButton.new("Show blocked requests")
    @rdo_passed = JRadioButton.new("Show passed requests")
    @rdo_all = JRadioButton.new("Show all (verbose)", true)
    grp_res = ButtonGroup.new()
    grp_res.add(@rdo_blocked)
    grp_res.add(@rdo_passed)
    grp_res.add(@rdo_all)
    
    @lay_scan.setHorizontalGroup(
      @lay_scan.createParallelGroup(GroupLayout::Alignment::LEADING
        ).addComponent(lbl_scan
        ).addComponent(lbl_scan_cont
        ).addComponent(@chk_encode
        ).addComponent(lbl_res_grp
        ).addComponent(@rdo_passed
        ).addComponent(@rdo_blocked
        ).addComponent(@rdo_all)
    )
    
    @lay_scan.setVerticalGroup(
      @lay_scan.createSequentialGroup(
        ).addComponent(lbl_scan
        ).addComponent(lbl_scan_cont
        ).addComponent(@chk_encode
        ).addComponent(lbl_res_grp
        ).addComponent(@rdo_passed
        ).addComponent(@rdo_blocked
        ).addComponent(@rdo_all)
    )
    
    # Finalize layout
    @lay_tgt.setHorizontalGroup(
      @lay_tgt.createParallelGroup(GroupLayout::Alignment::LEADING
        ).addComponent(@pan_waf
        ).addComponent(@pan_pay
        ).addComponent(@pan_scan)
    )
    
    @lay_tgt.setVerticalGroup(
      @lay_tgt.createSequentialGroup(
        ).addComponent(@pan_waf
        ).addComponent(@pan_pay
        ).addComponent(@pan_scan)
    )
    
    # Add Action Listeners
    @btn_pay_add.addActionListener do |e|
      addPayload(e)
    end
    @btn_pay_rem.addActionListener do |e|
      removePayload(e)
    end
    @btn_pay_cls.addActionListener do |e|
      clearPayload(e)
    end
    @btn_pay_def.addActionListener do |e|
      initPayloads
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
    
    lbl_passed = JLabel.new("<html><i>You can select a row then press Ctrl+C to copy its content or right-click on it and choose \"Send to repeater\"</i></html>")
    @tbl_res_model = MyTableModel.new()
    @tbl_res_model.addColumn("#")
    @tbl_res_model.addColumn("Blocked")
    @tbl_res_model.addColumn("Wordlist")
    @tbl_res_model.addColumn("Payload")
    @tbl_res_model.addColumn("HTTP Request")
    @tbl_res_model.addColumn("WTW Comment")
    @tbl_res = JTable.new(@tbl_res_model)
    
    @tbl_res.setDefaultRenderer(java.lang.String, MyTableRenderer.new())
    # @tbl_res.setDefaultRenderer(java.lang.Boolean, MyTableRenderer.new())
    
    @tbl_res.setFillsViewportHeight(true);
    @tbl_res.setSelectionMode(ListSelectionModel::SINGLE_SELECTION)
    @tbl_res.getColumnModel().getColumn(0).setPreferredWidth(50)
    @tbl_res.getColumnModel().getColumn(1).setPreferredWidth(20)
    @tbl_res.getColumnModel().getColumn(1).setPreferredWidth(100)
    @tbl_res.getColumnModel().getColumn(2).setPreferredWidth(300)
    @tbl_res.getColumnModel().getColumn(3).setPreferredWidth(300)
    @tbl_res.getColumnModel().getColumn(4).setPreferredWidth(500)
    @tbl_res.setAutoResizeMode(JTable::AUTO_RESIZE_OFF)    
    
    scroll_tbl = JScrollPane.new(@tbl_res)
    
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
    clearPayload
    
    paydir = File.expand_path(File.dirname(__FILE__)) + "/payloads/"
    @wordlist = {}
    Dir.glob(paydir+ "*.lsd") do |p|
      #JOptionPane.showMessageDialog(nil, p)
      @stdout.println("initPayloads => Adding file: " + p.to_s)
      #if File.extname(p) == ".lsd" then
        @wordlist[File.basename(p, ".*")] = p.to_s
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
  def removePayload(e)
    i = @lst_pay.getSelectedIndex()
    n = @lst_pay_model.getElementAt(i).to_s
    if (i != -1) and (@wordlist.has_key? n) then
        @wordlist.delete(n)
        @lst_pay_model.remove(i)
    end
  end
  
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def clearPayload(e = nil)
    @wordlist.clear unless @wordlist.nil?
    @lst_pay_model.removeAllElements() unless @lst_pay_model.nil?
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def loadEmAll
    @all_sent = []
    @total_index = 0
    @tbl_res_model.setRowCount(0)
    
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
    @all_processed = []
    @all_wordlists = []
    @n_payloads = 0
    
    # cell = @lst_pay.getSelectedValues()
    @wordlist.each do |k,v|
      ## TODO: Multi selection
      # next unless cell.find(k)
      # JOptionPane.showMessageDialog(nil, k + " - " + v)
      fsize = 0
      File.open(v, "rb").each do |l|
        l = l.chomp
        next if l.empty?
        fsize = fsize + 1
        @all_payloads[@n_payloads] = l
        @all_wordlists[@n_payloads] = k
        @n_payloads = @n_payloads + 1
      end
      @stdout.println("Loading: " + v + " - Size: " + fsize.to_s)
    end
    @all_result = Array.new(@n_payloads, false)
    @all_processed = Array.new(@n_payloads, false)
    
    @timeout = @txt_timeout.getText().to_s.to_i
    @block_page = @txt_block_url.getText().to_s
    @regex_str = @txt_body.getText().to_s
    @regex = Regexp.new @regex_str
    @reslen = @txt_len.getText().to_s.to_i
    
    @response = {}
    @chk.each do |c,b|
      @response[c] = @chk[c].isSelected()
    end
    
    @res_blocked = (@rdo_blocked.isSelected() or @rdo_all.isSelected())
    @res_passed = (@rdo_passed.isSelected() or @rdo_all.isSelected())
    @cur_pos = 0
    
    @stdout.println("loadEmAll: Starting attack with " + @n_payloads.to_s + " payloads")
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def addResult(w, d, p, r, c)
    begin
      @total_index = @total_index + 1
      @tbl_res_model.addRow([@total_index, d, w, p, r, c].to_java)
    rescue Exception => e
      @stderr.println e.message  
      @stderr.println e.backtrace.inspect 
    end
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def payloadIndex( pay )
    i = 0
    @all_payloads.each do |p|
      if p == pay then
        return i
      end
    end
    
    return i
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def payloadIndexInRequest(req )
    return -1 if @all_sent.nil?
    i = 0
    @all_sent.each do |s|
      if req.getComment().to_s.include? s then
        return i
      end
      i = i+1
    end
    
    return -1
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def detectTimeouts
    return if @timeout.nil?
    use_time = (@timeout > 0)
    
    if use_time then
      pos = 0
      @all_timestamp.each do |t|
        next if @all_result[pos]
        
        diff = Time.now.to_i - t - TIMEOUT_TRESH
        if diff > @timeout then
          @all_result[ pos ] = true
        
          comment = "WTW: Timeout"
        
          # if (detected and @res_blocked) or (not detected and @res_passed)
          # then
          addResult(
            @all_wordlists[ pos ],
            true,
            @all_payloads[ pos ], 
            "No response recieved from server in expected time",
            comment
          )
        end
        
        pos = pos + 1
      end
    end
  end
  
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
# -------------------------------------- BURP HOOKS ----------------------------------- #
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
  # String ITab::getTabCaption();
  def getTabCaption
    WTW_TAB_CAPTOIN
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  # String IIntruderPayloadProcessor::getProcessorName();
  def getProcessorName
    WTW_PRC_NAME
  end
  
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
  # String IIntruderPayloadGeneratorFactory::getGeneratorName();
  def getGeneratorName
    WTW_GEN_NAME
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
  # String ISessionHandlingAction::getActionName();
  def getActionName
    WTW_ACT_NAME
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
    @pg = PayGen.new(self)
    return @pg
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
    if not @pay_size.nil? and @pay_size > 0 and @pattern != "" then
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
    
    # @all_sent[ @pg.lastPos ] = random(8)
    return cs.to_java_bytes
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  # void IHttpListener::processHttpMessage(
  #   int toolFlag, 
  #   boolean messageIsRequest, 
  #   IHttpRequestResponse messageInfo);
  def processHttpMessage(toolFlag, messageIsRequest, messageInfo)
    return unless toolFlag == 0x20 # DUMMY!
    # return if messageInfo.getComment().to_s.downcase.include?("baseline")    
    # JOptionPane.showMessageDialog(nil, "RECV \n" + messageInfo.getComment().to_s)
    
    ## TODO
    if messageIsRequest and not @pg.nil? then
      messageInfo.setComment("Touched by WTW, id=" + @all_sent[@pg.lastPos])
      @pg.allowNext
    elsif not messageIsRequest and not @pg.nil? then
      pos = payloadIndexInRequest(messageInfo)
      
      if pos < 0 then
        @stdout.println("Not a WTW request")
        return
      end
      
      # JOptionPane.showMessageDialog(nil, "POS: " + pos.to_s + "RECV \n" + messageInfo.getResponse().to_s)
      @all_response[ @total_index ] = messageInfo
      ri = @helper.analyzeResponse( messageInfo.getResponse() )
      
      comment = ""
      
      # Check WAF
      use_code = false
      code_mathed = false
      use_redir = (@block_page.size > 0)
      redir_matched = false
      use_regex = (@regex_str.size > 0)
      regex_matched = false
      use_reslen = (@reslen > 0)
      reslen_matched = false
      
      # # Check HTTP status code
      @chk.each do |n,c|
        if c.isSelected() then
          use_code = true
          if n.to_i == ri.getStatusCode().to_i then
            code_mathed = true
            break
          end
        end
      end
      
      # # Check Block URL
      if use_redir then
        # JOptionPane.showMessageDialog(nil, "Size: " + @block_page.size.to_s + ", Value: " + @block_page)
        ri.getHeaders().each do |h|
          next if h.nil?
          
          # JOptionPane.showMessageDialog(nil, h.to_s)
          if h.to_s.size > 0 and 
             h.to_s.downcase.include? "location" and 
             h.to_s.downcase.include? @block_page.downcase 
          then
            redir_matched = true
          end
        end
      end
      
      # # Regex
      if use_regex then
        body = messageInfo.getResponse().to_s
        
        regex_matched = ( not @regex.match( body ).nil? )
      end
      
      # # Response Length
      if use_reslen then
        if @reslen == messageInfo.getResponse().size then
          reslen_matched = true
        end
      end
      
      # # Final Check
      detected = 
         ((use_code and code_mathed) or not use_code) and 
         ((use_redir and redir_matched) or not use_redir) and
         ((use_regex and regex_matched) or not use_regex) and
         ((use_reslen and reslen_matched) or not use_reslen) 
      @all_result[ pos ] = detected
            
      comment = comment + 
        ", DB: " + detected.to_s + 
        ", CM: " + code_mathed.to_s + 
        ", BM: " + redir_matched.to_s +
        ", XM: " + regex_matched.to_s +
        ", LM: " + reslen_matched.to_s
      
      if (detected and @res_blocked) or (not detected and @res_passed)
      then
        addResult(
          @all_wordlists[ pos ],
          detected,
          @all_payloads[ pos ], 
          messageInfo.getRequest().to_s,
          comment
        )
      end
      
      @all_processed[ pos ] = true
    end
    
    detectTimeouts
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  # void ISessionHandlingAction::performAction(
  #           IHttpRequestResponse currentRequest,
  #           IHttpRequestResponse[] macroItems);
  def performAction(currentRequest, macroItems)
    # TODO
  end
  
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  # void extensionUnloaded();
  def extensionUnloaded
    ## TODO
  end
end

