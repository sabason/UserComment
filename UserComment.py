from __future__ import print_function
import ida_idaapi
import ida_kernwin
import ida_idp
import ida_netnode
import idc
import ida_bytes
import ida_hexrays
import ida_nalt
import pickle
import ida_segment
import ida_funcs

title = "Comments"

# def show_warning(msg):
    # ida_kernwin.warning(msg)

class UserAddedComments():
    def __init__(self):
        self.netnode = ida_netnode.netnode()
        node_name = "$ user_comments"
        # 尝试获取现有的 netnode
        self.netnode = ida_netnode.netnode(node_name)
        if not self.netnode:
            # 如果不存在则创建新的
            self.netnode = ida_netnode.netnode()
            self.netnode.create(node_name)
        self.imagebase = ida_nalt.get_imagebase()
        if self.imagebase == ida_idaapi.BADADDR:
            self.imagebase = 0
        self.comments = {}
        self.load_comments()

    def save_comments(self):
        try:
            # 清理无效地址的注释
            valid_comments = {}
            for (offset, cmt_type, line_num), comment in self.comments.items():
                addr = offset + self.imagebase
                if addr != ida_idaapi.BADADDR and addr < 0xFFFFFFFFFFFFFFFF:
                    valid_comments[(offset, cmt_type, line_num)] = comment
            
            # 更新注释字典
            self.comments = valid_comments
            
            # 保存到数据库
            blob = pickle.dumps(self.comments)
            self.netnode.setblob(blob, 0, 'C')
            print(f"Saved {len(self.comments)} comments")
        except Exception as e:
            print(f"Save comments error: {e}")

    def load_comments(self):
        try:
            blob = self.netnode.getblob(0, 'C')
            if blob is not None:
                self.comments = pickle.loads(blob)
                print("加载的注释详情：")
                for (offset, cmt_type, line_num), comment in self.comments.items():
                    print(f"地址: {hex(offset + self.imagebase)}, 类型: {cmt_type}, 行号: {line_num}, 内容: {comment}")
            else:
                self.comments = {}
            print(f"总共加载了 {len(self.comments)} 条注释")
        except Exception as e:
            print(f"加载注释时出错: {e}")
            self.comments = {}

    def add_comment(self, ea, cmt_type, comment, line_num=None):
        try:
            # 确保地址有效
            if ea == ida_idaapi.BADADDR:
                print(f"Invalid address: {hex(ea)}")
                return
                
            offset = ea - self.imagebase
            key = (offset, cmt_type, line_num)
            
            # 确保注释是字符串类型
            if comment is not None:
                comment = str(comment)
            
            print(f"Adding comment at address {hex(ea)} (offset {hex(offset)})")
            print(f"Comment type: {cmt_type}, line: {line_num}, content: {comment}")
            
            if not comment:
                self.comments.pop(key, 0)
            else:
                self.comments[key] = comment
            self.save_comments()
        except Exception as e:
            print(f"Error in add_comment: {e}")

    def load_all_pseudocode_comments(self):
        try:
            # 遍历所有函数
            for func in ida_funcs.get_func_ranges():
                # 尝试反编译每个函数
                cfunc = ida_hexrays.decompile(func.start_ea)
                if cfunc:
                    # 获取该函数的所有用户注释
                    user_cmts = ida_hexrays.restore_user_cmts(cfunc.entry_ea)
                    if user_cmts:
                        for tl, cmt in user_cmts.items():
                            loc = ida_hexrays.treeloc_t()
                            loc.ea = tl.ea
                            loc.itp = tl.itp
                            # 保存注释
                            self.add_comment(loc.ea, 'pseudocode', cmt)
        except Exception as e:
            print(f"Error loading all pseudocode comments: {e}")

    def clear_invalid_comments(self):
        """清理所有无效地址的注释"""
        try:
            valid_comments = {}
            for (offset, cmt_type, line_num), comment in self.comments.items():
                addr = offset + self.imagebase
                if addr != ida_idaapi.BADADDR and addr < 0xFFFFFFFFFFFFFFFF:
                    valid_comments[(offset, cmt_type, line_num)] = comment
            
            self.comments = valid_comments
            self.save_comments()
            print(f"Cleaned up comments, {len(self.comments)} valid comments remaining")
        except Exception as e:
            print(f"Error clearing invalid comments: {e}")


class UIHooks(ida_kernwin.UI_Hooks):
    def __init__(self, cmt_view):
        ida_kernwin.UI_Hooks.__init__(self)
        self.cmt_view = cmt_view

    def current_widget_changed(self, widget, prev_widget):
        if ida_kernwin.get_widget_title(widget) == title:
            self.cmt_view.Refresh()


class PseudoHooks(ida_hexrays.Hexrays_Hooks):
    def __init__(self, usr_cmt):
        ida_hexrays.Hexrays_Hooks.__init__(self)
        self.usr_cmt = usr_cmt

    def func_printed(self, cfunc):
        try:
            # 当伪代码生成时加载注释
            user_cmts = ida_hexrays.restore_user_cmts(cfunc.entry_ea)
            if user_cmts:
                for tl, cmt in user_cmts.items():
                    loc = ida_hexrays.treeloc_t()
                    loc.ea = tl.ea
                    loc.itp = tl.itp
                    self.usr_cmt.add_comment(loc.ea, 'pseudocode', cmt)
            return 0
        except Exception as e:
            print(f"Error in func_printed: {e}")
            return 0

    def cmt_changed(self, cfunc, loc, cmt):
        try:
            self.usr_cmt.add_comment(loc.ea, 'pseudocode', cmt)
            return 0
        except Exception as e:
            print(f"Error in cmt_changed: {e}")
            return 0


class DisasmHooks(ida_idp.IDB_Hooks):
    def __init__(self, usr_cmt):
        ida_idp.IDB_Hooks.__init__(self)
        self.usr_cmt = usr_cmt
        self.rebased = False
        
    # 常规注释和可重复注释
    def changing_cmt(self, ea, is_repeatable, new_comment):
        try:
            cmt_type = 'repeatable' if is_repeatable else 'common'
            self.usr_cmt.add_comment(ea, cmt_type, new_comment)
            return 0
        except Exception as e:
            print(f"Error in changing_cmt: {e}")
            return 0
        
    # 前置注释和后置注释
    def extra_cmt_changed(self, ea, line_idx, cmt):
        try:
            if line_idx // 1000 == 1:  # 前置注释 (line_idx = 1xxx)
                self.usr_cmt.add_comment(ea, 'anterior', cmt, line_num=line_idx % 1000)
            elif line_idx // 1000 == 2:  # 后置注释 (line_idx = 2xxx)
                self.usr_cmt.add_comment(ea, 'posterior', cmt, line_num=line_idx % 1000)
            return 0
        except Exception as e:
            print(f"Error in extra_cmt_changed: {e}")
            return 0
        
    # 函数注释和可重复函数注释
    def changing_range_cmt(self, kind, a, cmt, repeatable):
        try:
            cmt_type = 'func_repeatable' if repeatable else 'func_common'
            self.usr_cmt.add_comment(a.start_ea, cmt_type, cmt)
            return 0
        except Exception as e:
            print(f"Error in changing_range_cmt: {e}")
            return 0
        
    # program image rebased
    def allsegs_moved(self, info):
        self.rebased = True
        self.usr_cmt.imagebase = ida_nalt.get_imagebase()
        
        
class CommentViewer(ida_kernwin.Choose):
    def __init__(self, usr_cmt):
        ida_kernwin.Choose.__init__(
            self,
            title,
            [ ["Address", 10 | ida_kernwin.Choose.CHCOL_HEX],
              ["Type", 20 | ida_kernwin.Choose.CHCOL_PLAIN],
              ["Comments", 30 | ida_kernwin.Choose.CHCOL_PLAIN]],
            flags = ida_kernwin.Choose.CH_CAN_REFRESH | ida_kernwin.Choose.CH_CAN_DEL)
        self.usr_cmt = usr_cmt
        self.items = []
        self.OnInit()

    def OnInit(self):
        try:
            self.items = []
            # 强制重新加载注释
            self.usr_cmt.load_comments()
            
            print(f"Comments count: {len(self.usr_cmt.comments)}")  # 调试信息
            
            for (offset, cmt_type, line_num), comment in self.usr_cmt.comments.items():
                if comment:  # 只添加非空注释
                    addr = offset + self.usr_cmt.imagebase
                    type_str = cmt_type
                    if line_num is not None:
                        type_str = f"{cmt_type}:{line_num}"
                    self.items.append([hex(addr), type_str, str(comment)])
            
            # 按地址排序
            self.items.sort(key=lambda x: int(x[0], 16))
            print(f"Loaded items: {len(self.items)}")  # 调试信息
            return True
        except Exception as e:
            print(f"OnInit error: {e}")
            return False

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]
        
    def OnRefresh(self, n):
        self.OnInit()
        if self.items:
            return [ida_kernwin.Choose.ALL_CHANGED] + self.adjust_last_item(n)
        return None # call standard refresh

    def OnSelectLine(self, n):
        selected_item = self.items[n]     # for single selection chooser
        addr = int(selected_item[0], 16)
        ida_kernwin.jumpto(addr)

    def OnDeleteLine(self, n):
        try:
            selected_item = self.items[n]
            addr = int(selected_item[0], 16)
            type_str = selected_item[1]
            
            # 解析注释类型和行号
            cmt_type = type_str
            line_num = None
            if ':' in type_str:
                cmt_type, line_num = type_str.split(':')
                line_num = int(line_num)
            
            # 调用 add_comment 传入空注释来删除
            self.usr_cmt.add_comment(addr, cmt_type, None, line_num)
            
            print(f"Deleted comment at {hex(addr)}, type: {cmt_type}")
            return [ida_kernwin.Choose.ALL_CHANGED]
        except Exception as e:
            print(f"Error deleting comment: {e}")
            return [ida_kernwin.Choose.NOTHING_CHANGED]


def register_open_action(cmt_view):
    """
    Provide the action that will create the widget
    when the user asks for it.
    """
    class create_widget_t(ida_kernwin.action_handler_t):
        def activate(self, ctx):
            cmt_view.Show()

        def update(self, ctx):
            return ida_kernwin.AST_ENABLE_ALWAYS

    action_name = "UserAddedComments:Show"
    action_shortcut = "Ctrl-Shift-C"
    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            action_name,
            title,
            create_widget_t(),
            action_shortcut))
    ida_kernwin.attach_action_to_menu(
        f"View/Open subviews/{title}",
        action_name,
        ida_kernwin.SETMENU_APP)


class my_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_HIDE                      # Plugin should not appear in the Edit, Plugins menu.
    wanted_name = "Hook and display user-added comments"
    wanted_hotkey = ""
    comment = "Hook and display user-added comments"
    help = ""
    
    def init(self):
        try:
            self.usr_cmt = UserAddedComments()
            # 清理无效注释
            self.usr_cmt.clear_invalid_comments()
            
            # 获取当前段的基址作为测试地址
            first_seg = ida_segment.get_first_seg()
            if first_seg:
                test_ea = first_seg.start_ea
                print(f"Testing with address: {hex(test_ea)}")
                #self.usr_cmt.add_comment(test_ea, 'common', "Test Comment 1")
                #self.usr_cmt.add_comment(test_ea + 4, 'repeatable', "Test Comment 2")
            
            # 确保钩子正确安装
            self.idb_hooks = DisasmHooks(self.usr_cmt)
            if not self.idb_hooks.hook():
                print("Failed to install IDB hooks")
            
            self.ray_hooks = PseudoHooks(self.usr_cmt)
            if not self.ray_hooks.hook():
                print("Failed to install Hexrays hooks")
            
            self.cmt_view = CommentViewer(self.usr_cmt)
            register_open_action(self.cmt_view)
            
            self.ui_hooks = UIHooks(self.cmt_view)
            if not self.ui_hooks.hook():
                print("Failed to install UI hooks")
            
            print("Plugin initialized successfully")
            return ida_idaapi.PLUGIN_KEEP
        except Exception as e:
            print(f"Plugin initialization error: {e}")
            return ida_idaapi.PLUGIN_SKIP

    def run(self, arg):
        #self.cmt_view.Show()
        pass
        
    def term(self):
        try:
            if hasattr(self, 'ui_hooks'):
                self.ui_hooks.unhook()
            if hasattr(self, 'ray_hooks'):
                self.ray_hooks.unhook()
            if hasattr(self, 'idb_hooks'):
                self.idb_hooks.unhook()
        except Exception as e:
            print(f"Plugin termination error: {e}")
        return


def PLUGIN_ENTRY():
    return my_plugin_t()