#ifndef slic3r_WebViewDialog_hpp_
#define slic3r_WebViewDialog_hpp_


#include "wx/artprov.h"
#include "wx/cmdline.h"
#include "wx/notifmsg.h"
#include "wx/settings.h"
#include <wx/webview.h>

#if wxUSE_WEBVIEW_EDGE
#include "wx/msw/webview_edge.h"
#endif

#include "wx/webviewarchivehandler.h"
#include "wx/webviewfshandler.h"
#include "wx/numdlg.h"
#include "wx/infobar.h"
#include "wx/filesys.h"
#include "wx/fs_arc.h"
#include "wx/fs_mem.h"
#include "wx/stdpaths.h"
#include <wx/panel.h>
#include <wx/tbarbase.h>
#include "wx/textctrl.h"
#include <wx/timer.h>


namespace Slic3r {

class NetworkAgent;

namespace GUI {


class WebViewPanel : public wxPanel
{
public:
    WebViewPanel(wxWindow *parent);
    virtual ~WebViewPanel();

    void load_url(wxString& url);

    void UpdateState();
    void OnIdle(wxIdleEvent& evt);
    void OnUrl(wxCommandEvent& evt);
    void OnBack(wxCommandEvent& evt);
    void OnForward(wxCommandEvent& evt);
    void OnStop(wxCommandEvent& evt);
    void OnReload(wxCommandEvent& evt);
    void OnNavigationRequest(wxWebViewEvent& evt);
    void OnNavigationComplete(wxWebViewEvent& evt);
    void OnDocumentLoaded(wxWebViewEvent& evt);
    void OnTitleChanged(wxWebViewEvent &evt);
    void OnNewWindow(wxWebViewEvent& evt);
    void OnScriptMessage(wxWebViewEvent& evt);
    void OnScriptResponseMessage(wxCommandEvent& evt);
    void OnViewSourceRequest(wxCommandEvent& evt);
    void OnViewTextRequest(wxCommandEvent& evt);
    void OnToolsClicked(wxCommandEvent& evt);
    void OnError(wxWebViewEvent& evt);
    void OnCut(wxCommandEvent& evt);
    void OnCopy(wxCommandEvent& evt);
    void OnPaste(wxCommandEvent& evt);
    void OnUndo(wxCommandEvent& evt);
    void OnRedo(wxCommandEvent& evt);
    void OnMode(wxCommandEvent& evt);
    void RunScript(const wxString& javascript);
    void OnRunScriptString(wxCommandEvent& evt);
    void OnRunScriptInteger(wxCommandEvent& evt);
    void OnRunScriptDouble(wxCommandEvent& evt);
    void OnRunScriptBool(wxCommandEvent& evt);
    void OnRunScriptObject(wxCommandEvent& evt);
    void OnRunScriptArray(wxCommandEvent& evt);
    void OnRunScriptDOM(wxCommandEvent& evt);
    void OnRunScriptUndefined(wxCommandEvent& evt);
    void OnRunScriptNull(wxCommandEvent& evt);
    void OnRunScriptDate(wxCommandEvent& evt);
    void OnRunScriptMessage(wxCommandEvent& evt);
    void OnRunScriptCustom(wxCommandEvent& evt);
    void OnAddUserScript(wxCommandEvent& evt);
    void OnSetCustomUserAgent(wxCommandEvent& evt);
    void OnClearSelection(wxCommandEvent& evt);
    void OnDeleteSelection(wxCommandEvent& evt);
    void OnSelectAll(wxCommandEvent& evt);
    void OnLoadScheme(wxCommandEvent& evt);
    void OnUseMemoryFS(wxCommandEvent& evt);
    void OnEnableContextMenu(wxCommandEvent& evt);
    void OnEnableDevTools(wxCommandEvent& evt);
    void OnClose(wxCloseEvent& evt);

    wxTimer * m_LoginUpdateTimer{nullptr};
    void OnFreshLoginStatus(wxTimerEvent &event);

public:
    void SendRecentList(int images);
    void SetLoginPanelVisibility(bool bshow);
    void SendDesignStaffpick(bool on);
    void OpenModelDetail(std::string id, NetworkAgent *agent);
    void SendLoginInfo();
    void ShowNetpluginTip();

// Snapmaker
    void sm_get_design_staffpic(int pageIndex = 1); // request the profile of models from snapmaker
    void sm_get_next_page_model(int pageIndex, std::string key = "");

    void sm_SwitchWebContent(std::string modelname, int refresh = 0);
    void sm_SwitchLeftMenu(std::string strMenu);

    void sm_OpenModelDetail(std::string id);

    void sm_get_search_model(std::string key, int pageIndex);

    void get_design_staffpick(int offset, int limit, std::function<void(std::string)> callback);
    int  get_model_mall_detail_url(std::string *url, std::string id);

    void update_mode();
private:

    wxWebView* m_browser;
    wxBoxSizer *bSizer_toolbar;
    wxButton *  m_button_back;
    wxButton *  m_button_forward;
    wxButton *  m_button_stop;
    wxButton *  m_button_reload;
    wxTextCtrl *m_url;
    wxButton *  m_button_tools;

    wxMenu* m_tools_menu;
    wxMenuItem* m_tools_handle_navigation;
    wxMenuItem* m_tools_handle_new_window;
    wxMenuItem* m_edit_cut;
    wxMenuItem* m_edit_copy;
    wxMenuItem* m_edit_paste;
    wxMenuItem* m_edit_undo;
    wxMenuItem* m_edit_redo;
    wxMenuItem* m_edit_mode;
    wxMenuItem* m_scroll_line_up;
    wxMenuItem* m_scroll_line_down;
    wxMenuItem* m_scroll_page_up;
    wxMenuItem* m_scroll_page_down;
    wxMenuItem* m_script_string;
    wxMenuItem* m_script_integer;
    wxMenuItem* m_script_double;
    wxMenuItem* m_script_bool;
    wxMenuItem* m_script_object;
    wxMenuItem* m_script_array;
    wxMenuItem* m_script_dom;
    wxMenuItem* m_script_undefined;
    wxMenuItem* m_script_null;
    wxMenuItem* m_script_date;
    wxMenuItem* m_script_message;
    wxMenuItem* m_script_custom;
    wxMenuItem* m_selection_clear;
    wxMenuItem* m_selection_delete;
    wxMenuItem* m_context_menu;
    wxMenuItem* m_dev_tools;

    wxInfoBar *m_info;
    wxStaticText* m_info_text;

    long m_zoomFactor;

    // Last executed JavaScript snippet, for convenience.
    wxString m_javascript;
    wxString m_response_js;

    DECLARE_EVENT_TABLE()
};

class SourceViewDialog : public wxDialog
{
public:
    SourceViewDialog(wxWindow* parent, wxString source);
};


class SnapmakerWorld
{
public:
    static SnapmakerWorld* GetInstance();

    void Get_Model_Detail(std::function<void(std::string)> callback, std::string model_id);

    void Get_Model_List(std::function<void(std::string)> callback,
                        int pageIndex,
                        std::string               name   = "",
                        std::string               userId = "" /*todo: timerange*/);

public:
    int GetPageSize() { return m_pageSize; }

private:
    SnapmakerWorld();

private:
    std::string m_host_url = "https://id.snapmaker.com/";

    std::map<std::string, std::string> m_api_url_map = {
        {"GET_MODEL_DETAIL", "api/model/info?modelId="},
        {"GET_MODEL_LIST", "api/model/list"},
    };

    int m_pageSize = 10;
};

} // GUI
} // Slic3r

#endif /* slic3r_Tab_hpp_ */
