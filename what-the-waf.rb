# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
# What The WAF?! extension for burp                                                     #
#                                                                                       #
# by _null_ (Sina Hatef)                                                                #
# source code (GPLv3) is available at github: https://github.com/null--/what-the-waf    #
#                                                                                       #
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
# TODO                                                                                  #
#   More informative error messages!                                                    #
#   Better exception handling                                                           #
#   TODO A handy panel to bypass WAF (after WAF weaknesses was discloused)              #
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
VERSION         = "1.4 (beta)"
DEBUG           = true
APP_ID          = "5da470c526ea4661a82187ec3e0f94aa"
WORDLIST_DIR    = "bapps/#{APP_ID}/wtw-repo/"

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
WTW_ACT_NAME    = "What The WAF?!"
WTW_GEN_NAME    = "What The WAF?!"
WTW_PRC_NAME    = "What The WAF?!"
WTW_TAB_CAPTOIN = "What The WAF?!"
TIMEOUT_TRESH   = 5

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
java_import java.awt.Toolkit
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
def COUT(str)
  # return if BurpExtender._BURP_STD_OUT_.nil?
  return unless DEBUG
  
  BurpExtender._BURP_STD_OUT_.println(str)
end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
def CERR(str)
  # return if BurpExtender._BURP_STD_ERR_.nil?
  
  BurpExtender._BURP_STD_ERR_.println(str)
end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
def random(len)
  (0...len).map { ('a'..'z').to_a[rand(26)] }.join
end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
# --------------------------------- MONSTER STATE ------------------------------------- #
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
class MonsterState
  attr_reader :id
  attr_reader :timestamp
  
  attr_accessor :allow
  
  attr_accessor :payload
  attr_accessor :wordlist
  
  attr_accessor :service
  attr_accessor :request
  attr_accessor :response
  
  attr_accessor :processed
  attr_accessor :detected
  
  attr_accessor :comment

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
  def initialize
    @id = random(8)
    @allow = false
    
    @comment = ""
    @processed = false
    @detected = false
    
    @service = nil
    @response = nil
    @request = nil
    
    @paylaod = ""
    @wordlist = ""
    
    setTime
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def setTime
    @timestamp = Time.now.to_i
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def age
    Time.now.to_i - @timestamp - TIMEOUT_TRESH
  end
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

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
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
      sendToRepeater(e)
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
  
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def sendToRepeater(e)
    row = @parent.tbl_res.getSelectedRow + 1
    
    @parent.burp.sendToRepeater(
      @parent.table_monster_map[row].service.getHost, 
      @parent.table_monster_map[row].service.getPort, 
      @parent.table_monster_map[row].service.getProtocol == "https", 
      @parent.table_monster_map[row].request,
      ("What The WAF?! #" + (row+1).to_s).to_java_string 
    )
  end
end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
# ------------------------------ PAYLOAD GENERATOR ------------------------------------ #
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
class PayGen
  include IIntruderPayloadGenerator
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  attr_accessor :cur_pos
  attr_accessor :parent

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def initialize(_p)
    @parent = _p
    reset
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  # boolean IIntruderPayloadGenerator::hasMorePayloads();
  def hasMorePayloads
    return (@cur_pos < @parent.monsters.size)
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  # byte[] IIntruderPayloadGenerator::getNextPayload(byte[] baseValue);
  def getNextPayload(baseValue)    
    while not @parent.monsters[@cur_pos].allow do
      # JOptionPane.showMessageDialog(nil, "Not allowed: " + @cur_pos.to_s + ": " + @allow[@cur_pos].to_s)
      COUT("Stucked for " + (@cur_pos).to_s)
      sleep(0.1)
    end
    
    @parent.monsters[@cur_pos].setTime
    p = @parent.monsters[@cur_pos].payload
    
    @cur_pos = @cur_pos + 1
    return p.to_java_bytes
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  # void IIntruderPayloadGenerator::reset();
  def reset
    @cur_pos = 0
    # @parent.loadEmAll
    
    @parent.monsters[0].allow = true unless @parent.monsters[0].nil?
    # @parent.monsters[1].allow = true unless @parent.monsters[1].nil?
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def lastPos
    @cur_pos - 1
  end
  
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def allowNext
    COUT("Allowing " + (@cur_pos+1).to_s)
    @parent.monsters[@cur_pos].allow = true if hasMorePayloads
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
  @@_BURP_STD_OUT_  = nil
  def self._BURP_STD_OUT_
    @@_BURP_STD_OUT_
  end
  @@_BURP_STD_ERR_  = nil
  def self._BURP_STD_ERR_
    @@_BURP_STD_ERR_
  end
  
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  attr_accessor :burp
  
  attr_accessor :tbl_res
  attr_accessor :tbl_res_model
  
  attr_accessor :stdout
  attr_accessor :stderr
  
  attr_accessor :monsters
  attr_accessor :table_monster_map
  
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
  def registerExtenderCallbacks(_burp)
    @monsters = []
    @table_monster_map = []
    @wordlist_pre = {}
    
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
    
    @@_BURP_STD_OUT_ = java.io.PrintWriter.new(@burp.getStdout(), true) if @@_BURP_STD_OUT_.nil?
    @@_BURP_STD_ERR_ = java.io.PrintWriter.new(@burp.getStderr(), true) if @@_BURP_STD_ERR_.nil?
    
    # gui
    # # tabs
    @tabs = JTabbedPane.new()
    
    initTargetUI
    initResultUI
    initReadmeUI
    
    initWordlists

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
    
    lbl_head = JLabel.new("<html><h3>README</h3><hr></html>")
    lbl_body = JLabel.new(
    "<html><h4>About</h4><hr><p>version: " + VERSION + 
    "<i><br>by _null_ (Sina Hatef)" + 
    "<br>Get the latest version from: <a href='https://github.com/null--/what-the-waf'>" + 
    "https://github.com/null--/what-the-waf</a></i>" + 
    "</p>" + 
    "<p><h4>How to use</h4><hr>" + 
    "1. This extension works beside Intruder, so send your target request to the Intruder " + 
    "and select your target parameter as you always do.<br>" + 
    "2. Goto \"Intruder\" tab then under \"Payloads\" tab select the \"Payload type\" to <b>\"Extension-generated\"</b><br>" + 
    "3. Under \"Payload Options\" section, click on \"select generator\" button and" + 
    "choose \"What the WAF?!\".<br>" + 
    "4. Under \"Payload Processing\" click \"add\" then select <b>\"Invoke Burp Extension\"" +
    "</b> and choose \"What The WAF?!\" as your paylaod processor. <br>" + 
    "5. Start Attack.</p>" + 
    "<p><h4>Note</h4><hr>" + 
    "1.On the \"Resuls\" tab you can select a row then right-click on it and choose " + 
    "\"Send to repeater\"<br>" + 
    "2. For advanced usage you may consider setting \"Throttle\" and/or " + 
    "\"Number of Threads\" optoins inside \"Intruder\" tab." + 
    "<br>(These two options are very useful against Advanced WAFs.<br>" + 
    "3. Examples are available at  <a href=\"https://github.com/null--/what-the-waf/tree/master/examples\">" + 
    "https://github.com/null--/what-the-waf/tree/master/examples</a>." + 
    "</p>" + 
    "<h4>Important Notes</h4><hr>" + 
    "<p>1. Current version does not support simultaneous Intruder attacks.<br>" + 
    "2. Scan one parameter at a time (<b>single param</b> + <b>sniper mode</b>)</p></html>")
    
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
    
    container.setLayout(BorderLayout.new) #(0, 200))
    container.setBorder(EmptyBorder.new( 3, 3, 3, 3 ) )
    
    @pan_tgt = JPanel.new()
    @lay_tgt = GroupLayout.new(@pan_tgt)
    @pan_tgt.setLayout(@lay_tgt)
    scroll = JScrollPane.new(@pan_tgt)
    container.add(scroll, BorderLayout::CENTER)
    # container.add(JPanel.new(BorderLayout::RIGHT) # GAP
    # # WAF PANEL # #
    @pan_waf = JPanel.new()
    @lay_waf = GroupLayout.new(@pan_waf)
    @lay_waf.setAutoCreateGaps(true)
    @lay_waf.setAutoCreateContainerGaps(true)
    @pan_waf.setLayout(@lay_waf)
    @pan_waf.setBorder(BorderFactory.createMatteBorder(0,0,2,0, Color.orange))
    lbl_hot = JLabel.new("<html><p>Be a professional and save your current Burp's state.</p></html>")
    lbl_waf = JLabel.new("<html><h3>WAF Options</h3><hr><br></html>")
    
    lbl_hcode = JLabel.new("<html><b>WAF HTTP Response Code</b><br><i>HTTP response code(s) used by WAF in response to a malicious request</i></html>")
    @chk = {}
    @chk["200"] = JCheckBox.new("<html>200: OK <i>(use this carefully)</i></html>")
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
    lbl_block_url = JLabel.new("<html><b>WAF Block/Redirection URL</b><br><i>After being detected, Where does WAF redirect you? (The value of \"Location:\" header)</i></html>")
    @txt_block_url = JTextField.new()
    lbl_timeout = JLabel.new("<html><b>Block timeout (seconds)</b></html>")
    @txt_timeout = JTextField.new("0")
    lbl_timeout_info = JLabel.new("<html><i>The connection timeout value used by WAF to block a malicious client.</i><b> (EXPERIMENTAL)</b></html>")
    lbl_body = JLabel.new("<html><b>Find in response body (REGEX)</b></html>")
    @txt_body = JTextField.new()
    lbl_len = JLabel.new("<html><b>Response length</b></html>")
    @txt_len = JTextField.new("0")
    lbl_len_info = JLabel.new("<html><i>0 = ignore response size</i></html>")
    
    @lay_waf.setHorizontalGroup(
      @lay_waf.createParallelGroup(GroupLayout::Alignment::LEADING
        ).addComponent(lbl_hot
        ).addComponent(lbl_waf
        ).addComponent(lbl_hcode
        ).addComponent(pan_code
        ).addComponent(lbl_block_url
        ).addComponent(@txt_block_url, 300, 500, 600 #)
        ).addComponent(lbl_timeout
        ).addComponent(lbl_timeout_info
        ).addComponent(@txt_timeout, 100, 100, 100 #)
        ).addComponent(lbl_body
        ).addComponent(@txt_body, 300, 500, 600 #)
        ).addComponent(lbl_len
        ).addComponent(lbl_len_info
        ).addComponent(@txt_len, 100, 100, 100)
    )
    
    @lay_waf.setVerticalGroup(
      @lay_waf.createSequentialGroup(
        ).addComponent(lbl_hot
        ).addComponent(lbl_waf
        ).addComponent(lbl_hcode
        ).addComponent(pan_code
        ).addComponent(lbl_block_url
        ).addComponent(@txt_block_url #)
        ).addComponent(lbl_timeout
        ).addComponent(lbl_timeout_info
        ).addComponent(@txt_timeout #)
        ).addComponent(lbl_body
        ).addComponent(@txt_body #)
        ).addComponent(lbl_len
        ).addComponent(lbl_len_info
        ).addComponent(@txt_len)
    )
    
    # # PAYLOAD PANEL # #
    @pan_pay = JPanel.new()
    @lay_pay = GroupLayout.new(@pan_pay)
    @lay_pay.setAutoCreateGaps(true)
    @lay_pay.setAutoCreateContainerGaps(true)
    @pan_pay.setLayout(@lay_pay)
    @pan_pay.setBorder(BorderFactory.createMatteBorder(0,0,2,0, Color.orange))
    lbl_pay = JLabel.new("<html><h3>Payload and Wordlist Options</h3><hr></html>")
    lbl_sel = JLabel.new("<html><h4>Wordlist</h4><hr><br>" + 
      "<i>Wrodlist files will be reloaded everytime you start a new Intruder attack.<br>" + 
      "There is no \"Select all\" button because it's not an option!</i></html>")
    
    @lst_pay_model = DefaultListModel.new()
    @lst_pay = JList.new(@lst_pay_model)
    @lst_pay.setSelectionMode(ListSelectionModel::SINGLE_SELECTION)
    @lst_pay_scr = JScrollPane.new(@lst_pay)
    
    @lst_pay_model_pre = DefaultListModel.new()
    @lst_pay_pre = JList.new(@lst_pay_model_pre)
    @lst_pay_pre.setSelectionMode(ListSelectionModel::SINGLE_SELECTION)
    @lst_pay_scr_pre = JScrollPane.new(@lst_pay_pre)
    
    lbl_pre = JLabel.new("<html><b>Available Wordlists</b></html>")
    lbl_post = JLabel.new("<html><b>Selected Wordlists</b></html>")
    
    @btn_insert = JButton.new("<html>&#92;<br>&#47;</html>")
    @btn_remove = JButton.new("<html>&#47;<br>&#92;</html>")
    
    lbl_pay_add = JLabel.new("<html><i>Add new wordlist (line-seperated list of paylaods)</i></html>")
    @btn_pay_add = JButton.new("Add")
    @btn_pay_rem = JButton.new("Remove")
    @btn_pay_cls = JButton.new("Clear")
    @btn_pay_def = JButton.new("Default")
    lbl_cont = JLabel.new("<html><h4>Payload Factory</h4><hr></html>")
    lbl_pay_size = JLabel.new("<html><b>Payload size</b></html>")
    @txt_pay_size = JTextField.new("0")
    lbl_pay_size_info = JLabel.new("<html><i>'0' = no \"Junk bytes\"!<br></i></html>")
    lbl_pay_pat = JLabel.new("<html><b>Junk bytes</b></html>")
    @txt_pay_pat = JTextField.new("")
    lbl_pay_pat_info = JLabel.new("<html><i>If the payload length is less than the \"Minimum payload size\" then this \"Junk bytes\" will be used to increase the size of payload.<br></i></html>")
    lbl_pat_grp = JLabel.new("<html><b>Position of Junk Bytes</b></html>")
    @rdo_pat_left = JRadioButton.new("Add \"Junk bytes\" to left side of payload")
    @rdo_pat_right = JRadioButton.new("Add \"Junk bytes\" to right side of payload", true)
    @rdo_pat_both = JRadioButton.new("Both sides")
    grp_pat = ButtonGroup.new()
    grp_pat.add(@rdo_pat_left)
    grp_pat.add(@rdo_pat_right)
    grp_pat.add(@rdo_pat_both)
    
    @lay_pay.setHorizontalGroup(
      @lay_pay.createParallelGroup(GroupLayout::Alignment::LEADING
        ).addComponent(lbl_pay
        ).addComponent(lbl_sel
        ).addGroup(@lay_pay.createSequentialGroup(
          ).addGroup(@lay_pay.createParallelGroup(GroupLayout::Alignment::LEADING
            ).addComponent(lbl_pre, 200, 200, 200
            ).addComponent(@lst_pay_scr_pre, 300, 300, 300)
          ).addGroup(@lay_pay.createParallelGroup(GroupLayout::Alignment::CENTER
            ).addComponent(@btn_insert, 50,50,50
            ).addComponent(@btn_remove, 50,50,50)
          ).addGroup(@lay_pay.createParallelGroup(GroupLayout::Alignment::LEADING
            ).addComponent(lbl_post, 200, 200, 200
            ).addComponent(@lst_pay_scr, 300, 300, 300)
          )
        ).addComponent(lbl_pay_add
        ).addGroup(@lay_pay.createSequentialGroup(
          ).addComponent(@btn_pay_add
          ).addComponent(@btn_pay_rem
          ).addComponent(@btn_pay_cls
          ).addComponent(@btn_pay_def)
        ).addComponent(lbl_cont
        ).addComponent(lbl_pay_size
        ).addComponent(lbl_pay_size_info
        ).addComponent(@txt_pay_size, 100, 100, 100 #)
        ).addComponent(lbl_pay_pat
        ).addComponent(lbl_pay_pat_info
        ).addComponent(@txt_pay_pat,300,300,300 #)
        ).addComponent(lbl_pat_grp
        ).addComponent(@rdo_pat_left
        ).addComponent(@rdo_pat_right
        ).addComponent(@rdo_pat_both)
    )
    
    @lay_pay.setVerticalGroup(
      @lay_pay.createSequentialGroup(
        ).addComponent(lbl_pay
        ).addComponent(lbl_sel
        ).addGroup(@lay_pay.createParallelGroup(GroupLayout::Alignment::CENTER
          ).addGroup(@lay_pay.createSequentialGroup(
            ).addComponent(lbl_pre
            ).addComponent(@lst_pay_scr_pre, 300, 300, 300)
          ).addGroup(@lay_pay.createSequentialGroup(
            ).addComponent(@btn_insert
            ).addComponent(@btn_remove)
          ).addGroup(@lay_pay.createSequentialGroup(
            ).addComponent(lbl_post
            ).addComponent(@lst_pay_scr, 300, 300, 300)
          )
        ).addComponent(lbl_pay_add
        ).addGroup(@lay_pay.createParallelGroup(GroupLayout::Alignment::BASELINE
          ).addComponent(@btn_pay_add
          ).addComponent(@btn_pay_rem
          ).addComponent(@btn_pay_cls
          ).addComponent(@btn_pay_def)
        ).addComponent(lbl_cont
        ).addComponent(lbl_pay_size
        ).addComponent(lbl_pay_size_info
        ).addComponent(@txt_pay_size #)
        ).addComponent(lbl_pay_pat
        ).addComponent(lbl_pay_pat_info
        ).addComponent(@txt_pay_pat #)
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
    lbl_scan = JLabel.new("<html><h3>Scan Options</h3><hr></html>")
    @chk_encode = JCheckBox.new("Force URL-encoding", false)
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
      addWordlist(e)
    end
    @btn_pay_rem.addActionListener do |e|
      removeWordlist(e)
    end
    @btn_pay_cls.addActionListener do |e|
      clearWordlists(e)
    end
    @btn_pay_def.addActionListener do |e|
      initWordlists
    end
    
    @btn_insert.addActionListener do |e|
      selectWordlist(e)
    end
    @btn_remove.addActionListener do |e|
      unselectWordlist(e)
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
    
    lbl_passed = JLabel.new(
        "<html><i>1. If you want to save HTTP requests/responses," + 
        " you can use the \"Save\" menu inside \"Intruder Attack\" window.<br>" + 
        "2. You can select a row then press Ctrl+C to copy " +
        "its content or right-click on it and choose \"Send to repeater\"</i></html>")
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
    @tbl_res.getColumnModel().getColumn(1).setPreferredWidth(70)
    @tbl_res.getColumnModel().getColumn(2).setPreferredWidth(200)
    @tbl_res.getColumnModel().getColumn(3).setPreferredWidth(200)
    @tbl_res.getColumnModel().getColumn(4).setPreferredWidth(300)
    @tbl_res.getColumnModel().getColumn(5).setPreferredWidth(500)
    @tbl_res.setAutoResizeMode(JTable::AUTO_RESIZE_OFF)    
    
    scroll_tbl = JScrollPane.new(@tbl_res)
    
    @btn_save = JButton.new("Save Results (tab-seperated file)")
    
    @lay_res.setHorizontalGroup(
      @lay_res.createParallelGroup(GroupLayout::Alignment::LEADING
        ).addComponent(@btn_save
        ).addComponent(lbl_passed
        ).addComponent(scroll_tbl)
    )
    
    @lay_res.setVerticalGroup(
      @lay_res.createSequentialGroup(
        ).addComponent(@btn_save
        ).addComponent(lbl_passed
        ).addComponent(scroll_tbl)
    )
    
    @mouse_handler = ResultMouse.new
    @mouse_handler.createMenu(self)
    @tbl_res.addMouseListener( @mouse_handler )
    
    @btn_save.addActionListener do |e|
      saveResult(e)
    end
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def initWordlists
    clearWordlists
    
    paydir = File.expand_path(File.dirname(__FILE__)) + "/#{WORDLIST_DIR}"
    @wordlist = {}
    
    no_file = true
    try_it = 3
    while no_file and try_it > 0 do
      Dir.glob(paydir+ "*.lsd").sort().each do |p|
        no_file = false
        #JOptionPane.showMessageDialog(nil, p)
        COUT("initWordlists => Adding file: " + p.to_s)
        #if File.extname(p) == ".lsd" then
          @wordlist_pre[File.basename(p, ".*")] = p.to_s
          @lst_pay_model_pre.addElement(File.basename(p, ".*"))
        #end
      end
      
      if no_file then
        JOptionPane.showMessageDialog(nil, 
          "<html>Cannot find WTW's default wordlists (those .lsd files inside #{WORDLIST_DIR})<br>" + 
          "Please copy #{WORDLIST_DIR}* to #{paydir}<br>" +
          "(WTW directory: <b>#{paydir}</b>)<br>" + 
          "Try again! (#{try_it})</html>",
          "Warning...",
          JOptionPane::WARNING_MESSAGE)
      end
      
      try_it = try_it - 1
    end
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def addWordlist(e)
    fc = JFileChooser.new()
    fc.setFileFilter(WordlistFilter.new())
    
    if fc.showOpenDialog(@tabs) == JFileChooser::APPROVE_OPTION then
      p = fc.getSelectedFile().to_s
      @wordlist_pre[File.basename(p, ".*")] = p
      @lst_pay_model_pre.addElement(File.basename(p, ".*"))
    end
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def removeWordlist(e)
    i = @lst_pay_pre.getSelectedIndex()
    n = @lst_pay_model_pre.getElementAt(i).to_s
    if (i != -1) and (@wordlist.has_key? n) then
        @wordlist_pre.delete(n)
        @lst_pay_model_pre.remove(i)
    end
  end
  
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def clearWordlists(e = nil)
    @wordlist.clear unless @wordlist.nil?
    @wordlist_pre.clear unless @wordlist_pre.nil?
    @lst_pay_model_pre.removeAllElements() unless @lst_pay_model_pre.nil?
    @lst_pay_model.removeAllElements() unless @lst_pay_model.nil?
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
  def selectWordlist(e)
    i = @lst_pay_pre.getSelectedIndex()
    n = @lst_pay_model_pre.getElementAt(i).to_s
    if (i != -1) then
        @lst_pay_model_pre.remove(i)
        @lst_pay_model.addElement(n)
        @wordlist[n] = @wordlist_pre[n]
        @wordlist_pre.delete(n)
    end
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #
  def unselectWordlist(e)
    i = @lst_pay.getSelectedIndex()
    n = @lst_pay_model.getElementAt(i).to_s
    if (i != -1) then
        @lst_pay_model.remove(i)
        @lst_pay_model_pre.addElement(n)
        @wordlist_pre[n] = @wordlist[n]
        @wordlist.delete(n)
    end
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def saveResult(e)
    fc = JFileChooser.new()
    
    if fc.showSaveDialog(@tabs) == JFileChooser::APPROVE_OPTION then
      p = fc.getSelectedFile().to_s
      
      File.open(p, "w+") do |f|
        0.upto(3) do |i|
          f << @tbl_res.getColumnName(i).to_s << "\t"
        end
        f << "\n"
        
        0.upto(@tbl_res.getRowCount().to_i) do |i|
          0.upto(3) do |j|
            f << @tbl_res.getValueAt(i, j) << "\t"
          end
          f << "\n"
        end
      end
    end
  end
  
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def loadEmAll
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
    @monsters.clear
    
    n = 0
    @wordlist.each do |k,v|
      fsize = 0
      File.open(v, "rb").each do |l|
        l = l.chomp
        next if l.empty?
        next if l.include? "###"
        
        fsize = fsize + 1
        
        @monsters[n] = MonsterState.new
        @monsters[n].payload = l
        @monsters[n].wordlist = k
        n = n + 1
      end
      COUT("Loaded: " + v + " - Size: " + fsize.to_s)
    end
    
    @timeout = @txt_timeout.getText().to_s.to_i
    @block_page = @txt_block_url.getText().to_s
    @regex_str = @txt_body.getText().to_s
    @regex = Regexp.new @regex_str
    @reslen = @txt_len.getText().to_s.to_i
    
    @resp_code = {}
    @chk.each do |c,b|
      @resp_code[c] = @chk[c].isSelected()
    end
    
    @res_blocked = (@rdo_blocked.isSelected() or @rdo_all.isSelected())
    @res_passed = (@rdo_passed.isSelected() or @rdo_all.isSelected())
    
    COUT("loadEmAll: Starting attack with " + @monsters.size.to_s + " payloads")
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def addResult( a_monster )
    begin
      if a_monster.response.nil? then
        resp = "No response recieved from server in expected time" 
      else
        resp = a_monster.response.to_s
      end
      
      @total_index = @total_index + 1
      @tbl_res_model.addRow([
        @total_index, 
        a_monster.detected, 
        a_monster.wordlist, 
        a_monster.payload,
        resp, 
        a_monster.comment].to_java)
        
      @table_monster_map[ @total_index ] = a_monster
    rescue Exception => e
      CERR e.message  
      CERR e.backtrace.inspect 
    end
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def payloadIndex( pay )
    i = 0
    @monsters.each do |p|
      if p == pay then
        return i
      end
    end
    
    return i
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  def findMonster(req )
    return -1 if @monsters.nil?
    i = 0
    @monsters.each do |m|
      if req.getComment().to_s.include? m.id then
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
      ## TODO: Is this accurate?
      pos = 0
      @monsters.each do |m|
        next if m.processed
        next if m.request.nil?
        
        diff = m.age
        if diff > @timeout then
          m.processed = true
          m.detected = true
          m.response = nil
          m.comment = "WTW: Timeout"
          
          addResult(m)
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
    ## TODO: Test logical flow
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
    
    return cs.to_java_bytes
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  # void IHttpListener::processHttpMessage(
  #   int toolFlag, 
  #   boolean messageIsRequest, 
  #   IHttpRequestResponse messageInfo);
  def processHttpMessage(toolFlag, messageIsRequest, messageInfo)
    return unless toolFlag == 0x20 # DUMMY!    
    ## TODO: Test logical flow
    if messageIsRequest and not @pg.nil? and @pg.lastPos >= 0 then
      COUT("Preparing the monster")
      
      @monsters[@pg.lastPos].setTime
      @monsters[@pg.lastPos].request = messageInfo.getRequest()
      @monsters[@pg.lastPos].service = messageInfo.getHttpService()
      
      messageInfo.setComment("Touched by WTW, id=" + @monsters[@pg.lastPos].id)
      COUT "Monster #" + @monsters[@pg.lastPos].id + " is unleashed!"
      
      @pg.allowNext
    elsif not messageIsRequest and not @pg.nil? then
      pos = findMonster(messageInfo)
      
      if pos < 0 then
        COUT("Not a WTW request")
        return
      end
      
      @monsters[pos].response = messageInfo.getResponse
      
      # JOptionPane.showMessageDialog(nil, "POS: " + pos.to_s + "RECV \n" + messageInfo.getResponse().to_s)
      ri = @helper.analyzeResponse( messageInfo.getResponse() )
      
      comment = ""
      
      # Check WAF
      use_code        = false
      code_mathed     = false
      use_redir       = (@block_page.size > 0)
      redir_matched   = false
      use_regex       = (@regex_str.size > 0)
      regex_matched   = false
      use_reslen      = (@reslen > 0)
      reslen_matched  = false
      
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
      @monsters[pos].detected = 
         ((use_code and code_mathed) or not use_code) and 
         ((use_redir and redir_matched) or not use_redir) and
         ((use_regex and regex_matched) or not use_regex) and
         ((use_reslen and reslen_matched) or not use_reslen) 
      @monsters[pos].comment = comment + 
        ", DB: " + @monsters[pos].detected.to_s + 
        ", CM: " + code_mathed.to_s + 
        ", BM: " + redir_matched.to_s +
        ", XM: " + regex_matched.to_s +
        ", LM: " + reslen_matched.to_s
      
      if (@monsters[pos].detected and @res_blocked) or 
         (not @monsters[pos].detected and @res_passed)
      then
        addResult(@monsters[pos])
      end
      
      @monsters[ pos ].processed = true
      
      ## TODO: Wrong place, Buggy!
      detectTimeouts unless @pg.nil? or @pg.hasMorePayloads
    end
  end

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  # void ISessionHandlingAction::performAction(
  #           IHttpRequestResponse currentRequest,
  #           IHttpRequestResponse[] macroItems);
  def performAction(currentRequest, macroItems)
    ## TODO: Is it better to use this method instead of processHttpMessage?
  end
  
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- #  
  # void extensionUnloaded();
  def extensionUnloaded
    ## TODO: Nothing, yet!
  end
end
