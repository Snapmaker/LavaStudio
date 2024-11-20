#ifndef slic3r_SnapmakerWorld_hpp_
#define slic3r_SnapmakerWorld_hpp_
#include "wx/artprov.h"
#include "wx/cmdline.h"
#include "wx/notifmsg.h"
#include "wx/settings.h"
#include <wx/webview.h>

#include <thread>
#include <mutex>
#include <condition_variable>

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

#include "GUI_App.hpp"

namespace Slic3r {

class NetworkAgent;

namespace GUI {

class SnapmakerWorld
{
public:
    ~SnapmakerWorld();

    static SnapmakerWorld* GetInstance();

    void Get_Model_Detail(std::function<void(std::string)> callback, std::string model_id);

    void Get_Model_List(std::function<void(std::string)> callback,
                        int pageIndex,
                        std::string               name   = "",
                        std::string               userId = "" /*todo: timerange*/);

public:
    // abount login and user status
    void Update_Login_State(std::function<void(bool)> callback, std::string token);

    void read_userInfos();

    void        write_userInfos(GUI_App::SMUserInfo& info);
    static void check_write_task_queue(SnapmakerWorld* obj);
    void        add_target(GUI_App::SMUserInfo& info);

public:
    int GetPageSize() { return m_pageSize; }

private:
    SnapmakerWorld();

private:
    // 3DES 
    // util
    std::vector<unsigned char> Encrypt(const std::string& plaintext, const std::string& key);

    std::string Decrypt(const std::vector<unsigned char>& ciphertext, const std::string& key);

private:
    // write user_info to file
    std::thread* m_write_engine_thread = nullptr;

    std::queue<GUI_App::SMUserInfo> m_write_task_queue;

    std::string m_afs_key = "SnapmakerOrcaSnapmakerOr";

    bool m_task_finish = false;

public:
    static std::mutex              mtx; // 互斥锁
    static std::mutex              task_finish_mtx;
    static std::condition_variable cv;  // 条件变量


private:
    std::string m_host_url = "https://id.snapmaker.com/";
    std::string                        m_check_token_ulr = "";
    std::map<std::string, std::string> m_api_url_map = {
        {"GET_MODEL_DETAIL", "api/model/info?modelId="},
        {"GET_MODEL_LIST", "api/model/list"},
    };

    int m_pageSize = 10;
};

} // GUI
} // Slic3r

#endif /* slic3r_Tab_hpp_ */
