#include "WebViewDialog.hpp"
#include "SnapmakerWorld.hpp"

#include "I18N.hpp"
#include "slic3r/GUI/wxExtensions.hpp"
#include "slic3r/GUI/GUI_App.hpp"
#include "slic3r/GUI/MainFrame.hpp"
#include "libslic3r_version.h"
#include "../Utils/Http.hpp"

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <wx/sizer.h>
#include <wx/toolbar.h>
#include <wx/textdlg.h>
#include <wx/url.h>

#include <slic3r/GUI/Widgets/WebView.hpp>

#include "boost/algorithm/hex.hpp"
#include "openssl/aes.h"
#include "openssl/rand.h"
#include "openssl/evp.h"

namespace pt = boost::property_tree;

namespace Slic3r {
namespace GUI {

std::mutex SnapmakerWorld::mtx;
std::mutex SnapmakerWorld::task_finish_mtx;

std::condition_variable SnapmakerWorld::cv;

SnapmakerWorld::SnapmakerWorld() {
    m_write_engine_thread  = new thread(SnapmakerWorld::check_write_task_queue, this);
}

SnapmakerWorld::~SnapmakerWorld() {
    std::unique_lock<std::mutex> lock(task_finish_mtx);
    m_task_finish = true;
    lock.unlock();

    m_write_engine_thread->join();
    delete m_write_engine_thread;
}

SnapmakerWorld* SnapmakerWorld::GetInstance()
{
    static SnapmakerWorld instance;
    return &instance;
}

void SnapmakerWorld::Get_Model_Detail(std::function<void(std::string)> callback, std::string model_id)
{
    // https: // id.snapmaker.com/api/model/info?modelId=
    auto http = Http::get(m_host_url + m_api_url_map["GET_MODEL_DETAIL"] + model_id);
    http.on_complete([&, callback](std::string body, unsigned status) {
            json j_body = json::parse(body);
            if (j_body.count("msg") && j_body["msg"].get<std::string>() == "success") {
                if (j_body.count("data")) {
                    // test 默认头像
                    j_body["data"]["creatorAvator"] =
                        "https://tse2-mm.cn.bing.net/th/id/OIP-C.bnFrKPm24qmFqvy61PecWwAAAA?rs=1&pid=ImgDetMain";
                    auto result = j_body["data"].dump();

                    wxGetApp().CallAfter([callback, result] { callback(result); });
                }
            }
        })
        .on_error([&](std::string body, std::string error, unsigned status) {})
        .perform();
}

void SnapmakerWorld::Update_Login_State(std::function<void(bool)> callback, std::string token)
{
    std::string url  = "https://account.snapmaker.com/api/common/accounts/current";
    auto        http = Http::get(url);
    http.header("authorization", token);
    http.on_complete([&, callback](std::string body, unsigned status) {
            if (status == 200) {
                json response = json::parse(body);
                wxGetApp().CallAfter([this, response, callback]() {
                    if (response.count("code")) {
                        json code     = response["code"];
                        int  int_code = code.get<int>();
                        if (int_code != 200) {
                            callback(false);
                        } else {
                            if (response.count("data")) {
                                json data = response["data"];
                                if (data.count("nickname")) {
                                    wxGetApp().sm_get_userinfo()->set_user_name(data["nickname"].get<std::string>());
                                }
                                if (data.count("icon")) {
                                    wxGetApp().sm_get_userinfo()->set_user_icon_url(data["icon"].get<std::string>());
                                }

                                wxGetApp().sm_get_userinfo()->set_user_info_time((long long) (wxDateTime::Now().GetTicks()));
                                wxGetApp().update_userInfos(true);
                            }
                            callback(true);
                        }
                    }
                });
            }
        })
        .on_error([&](std::string body, std::string error, unsigned status) {

        })
        .perform();
}

void SnapmakerWorld::Get_Model_List(std::function<void(std::string)> callback, int pageIndex, std::string name, std::string userId)
{
    // https://id.snapmaker.com/api/model/list
    auto http = Http::post(m_host_url + m_api_url_map["GET_MODEL_LIST"]);
    // auto http = Http::post("http://172.17.100.32/api/model/list");
    json param;
    param["pageIndex"] = pageIndex;
    // param["pageRows"]  = m_pageSize;
    param["pageRows"] = 5;
    if (name != "") {
        param["name"] = name;
    }
    if (userId != "") {
        param["userId"] = userId;
    }

    http.header("Content-Type", "application/json")
        .set_post_body(param.dump())
        .on_complete([&, callback](std::string body, unsigned status) {
            json j_body = json::parse(body);
            json response;
            response["hits"] = json::array();
            if (j_body.count("data")) {
                for (size_t i = 0; i < j_body["data"].size(); ++i) {
                    json record = j_body["data"];
                    json ans;
                    ans["design"] = json::object();

                    ans["design"]["id"]                    = record[i]["modelId"];
                    ans["design"]["title"]                 = record[i]["name"];
                    ans["design"]["titleTranslated"]       = ""; // todo
                    ans["design"]["cover"]                 = record[i]["thumbnail"];
                    ans["design"]["likeCount"]             = 159; // todo
                    ans["design"]["collectionCount"]       = 509; // todo
                    ans["design"]["shareCount"]            = 0;   // todo
                    ans["design"]["printCount"]            = 387; // todo
                    ans["design"]["downloadCount"]         = 211; // todo
                    ans["design"]["commentCount"]          = 13;  // todo
                    ans["design"]["readCount"]             = 0;   // todo
                    ans["design"]["designCreator"]         = json::object();
                    ans["design"]["designCreator"]["uid"]  = record[i]["creatorId"];
                    ans["design"]["designCreator"]["name"] = record[i]["creator"];
                    ans["design"]["designCreator"]["avatar"] =
                        "https://tse2-mm.cn.bing.net/th/id/OIP-C.bnFrKPm24qmFqvy61PecWwAAAA?rs=1&pid=ImgDetMain"; // todo
                    ans["design"]["designCreator"]["fanCount"]     = 129;                                         // todo
                    ans["design"]["designCreator"]["followCount"]  = 229;                                         // todo
                    ans["design"]["designCreator"]["createTime"]   = "2024-04-24T04:17:34Z";
                    ans["design"]["designCreator"]["certificated"] = false;

                    response["hits"].push_back(ans);
                }

                std::string result = response.dump();

                wxGetApp().CallAfter([result, callback] { callback(result); });
            }
        })
        .on_error([&](std::string body, std::string error, unsigned status) {

        })
        .perform();
}

std::vector<unsigned char> SnapmakerWorld::Encrypt(const std::string& plaintext, const std::string& key)
{
    if (key.length() != 24) {
        return {};
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return {};
    }

    // Generate a random IV
    unsigned char iv[EVP_MAX_IV_LENGTH];
    if (!RAND_bytes(iv, sizeof(iv))) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    // Initialize the encryption context with the cipher and IV
    if (1 != EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, reinterpret_cast<const unsigned char*>(key.c_str()), iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    // Calculate the buffer size for ciphertext
    int                        len            = plaintext.length();
    int                        ciphertext_len = len + EVP_MAX_BLOCK_LENGTH;
    std::vector<unsigned char> ciphertext(ciphertext_len);

    // Perform the encryption
    int outlen = 0;
    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen, reinterpret_cast<const unsigned char*>(plaintext.c_str()), len)) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    // Finalize the encryption
    int final_len = 0;
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen, &final_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    // Resize the ciphertext to the actual length
    ciphertext.resize(outlen + final_len);

    // Prepend the IV to the ciphertext
    std::vector<unsigned char> result(iv, iv + sizeof(iv));
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());

    return result;
}

std::string SnapmakerWorld::Decrypt(const std::vector<unsigned char>& ciphertext_with_iv, const std::string& key)
{
    if (key.length() != 24 || ciphertext_with_iv.size() < EVP_MAX_IV_LENGTH) {
        return "";
    }

    const unsigned char*             iv = ciphertext_with_iv.data();
    const std::vector<unsigned char> ciphertext(ciphertext_with_iv.begin() + EVP_MAX_IV_LENGTH, ciphertext_with_iv.end());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return "";
    }

    // Initialize the decryption context with the cipher, key, and IV
    if (1 != EVP_DecryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, reinterpret_cast<const unsigned char*>(key.c_str()), iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    // Calculate the buffer size for plaintext
    int         len           = ciphertext.size();
    int         plaintext_len = len + EVP_MAX_BLOCK_LENGTH;
    std::string plaintext(plaintext_len, '\0');

    // Perform the decryption
    int outlen = 0;
    if (1 != EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]), &outlen, ciphertext.data(), len)) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    // Finalize the decryption
    int final_len = 0;
    if (1 != EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&plaintext[outlen]), &final_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    // Resize the plaintext to the actual length
    plaintext.resize(outlen + final_len);

    return plaintext;
}

void SnapmakerWorld::read_userInfos() {
    auto userInfo_folder = boost::filesystem::path(data_dir()) / "sm_user_infos";
    if (!boost::filesystem::exists(userInfo_folder)) {
        boost::filesystem::create_directory(userInfo_folder);
    }

    for (boost::filesystem::directory_iterator it(userInfo_folder); it != boost::filesystem::directory_iterator(); ++it) {
        if (!it->is_directory() && boost::filesystem::extension(it->path()) == ".enc") {
            std::ifstream file(it->path().string(), std::ios::in);
            if (file) {
                std::string line;
                int         index = 0;
                std::string encrypted_userId_hex, encrypted_username_hex, encrypted_token_hex, encrypted_time_hex, encrypted_icon_hex,
                    encrypted_islogin_hex, encrypted_account_hex;
                while (std::getline(file, line)) {
                    switch (index % 7) {
                    case 0: encrypted_userId_hex = line; break;
                    case 1: encrypted_username_hex = line; break;
                    case 2: encrypted_token_hex = line; break;
                    case 3: encrypted_time_hex = line; break;
                    case 4: encrypted_icon_hex = line; break;
                    case 5: encrypted_islogin_hex = line; break;
                    default: encrypted_account_hex = line; break;
                    }
                    ++index;
                }
                std::vector<unsigned char> encrypted_userId, encrypted_username, encrypted_token, encrypted_time, encrypted_icon,
                    encrypted_islogin, encrypted_account;
                boost::algorithm::unhex(encrypted_userId_hex.begin(), encrypted_userId_hex.end(), std::back_inserter(encrypted_userId));
                boost::algorithm::unhex(encrypted_username_hex.begin(), encrypted_username_hex.end(),
                                        std::back_inserter(encrypted_username));
                boost::algorithm::unhex(encrypted_token_hex.begin(), encrypted_token_hex.end(), std::back_inserter(encrypted_token));
                boost::algorithm::unhex(encrypted_time_hex.begin(), encrypted_time_hex.end(), std::back_inserter(encrypted_time));
                boost::algorithm::unhex(encrypted_icon_hex.begin(), encrypted_icon_hex.end(), std::back_inserter(encrypted_icon));
                boost::algorithm::unhex(encrypted_islogin_hex.begin(), encrypted_islogin_hex.end(), std::back_inserter(encrypted_islogin));
                boost::algorithm::unhex(encrypted_account_hex.begin(), encrypted_account_hex.end(), std::back_inserter(encrypted_account));

                GUI_App::SMUserInfo  userInfo;
                std::string key = m_afs_key;
                userInfo.set_user_login_id(std::atoll(Decrypt(encrypted_userId, key).c_str()));
                userInfo.set_user_name(Decrypt(encrypted_username, key));
                userInfo.set_user_token(Decrypt(encrypted_token, key));
                userInfo.set_user_icon_url(Decrypt(encrypted_icon, key));
                userInfo.set_user_login(Decrypt(encrypted_islogin, key) == "false" ? false : true);
                userInfo.set_user_info_time(std::atoll(Decrypt(encrypted_time, key).c_str()));
                userInfo.set_user_account(Decrypt(encrypted_account, key));

                wxGetApp().m_userInfos.insert({userInfo.get_user_login_id(), userInfo});
            }
            file.close();
        }
    }
}

void SnapmakerWorld::write_userInfos(GUI_App::SMUserInfo& info) {
    auto userInfo_folder = boost::filesystem::path(data_dir()) / "sm_user_infos";
    if (!boost::filesystem::exists(userInfo_folder)) {
        boost::filesystem::create_directory(userInfo_folder);
    }

    boost::filesystem::path user_file(userInfo_folder / (info.get_user_account() + ".enc"));
    std::ofstream           ofs(user_file.string(), std::ios::out);

    auto encrypt_userId   = Encrypt(std::to_string(info.get_user_login_id()), m_afs_key);
    auto encrypt_username = Encrypt(info.get_user_name(), m_afs_key);
    auto encrypt_token    = Encrypt(info.get_user_token(), m_afs_key);
    auto encrypt_time     = Encrypt(std::to_string(info.get_user_info_time()), m_afs_key);
    auto encrypt_icon     = Encrypt(info.get_user_icon_url(), m_afs_key);
    auto encrypt_islogin  = Encrypt(info.is_user_login() ? "true" : "false", m_afs_key);
    auto encrypt_account  = Encrypt(info.get_user_account(), m_afs_key);

    std::string encrypt_userId_hex;
    std::string encrypt_username_hex;
    std::string encrypt_token_hex;
    std::string encrypt_time_hex;
    std::string encrypt_icon_hex;
    std::string encrypt_islogin_hex;
    std::string encrypt_account_hex;

    boost::algorithm::hex(encrypt_userId.begin(), encrypt_userId.end(), std::back_inserter(encrypt_userId_hex));
    boost::algorithm::hex(encrypt_username.begin(), encrypt_username.end(), std::back_inserter(encrypt_username_hex));
    boost::algorithm::hex(encrypt_token.begin(), encrypt_token.end(), std::back_inserter(encrypt_token_hex));
    boost::algorithm::hex(encrypt_time.begin(), encrypt_time.end(), std::back_inserter(encrypt_time_hex));
    boost::algorithm::hex(encrypt_icon.begin(), encrypt_icon.end(), std::back_inserter(encrypt_icon_hex));
    boost::algorithm::hex(encrypt_islogin.begin(), encrypt_islogin.end(), std::back_inserter(encrypt_islogin_hex));
    boost::algorithm::hex(encrypt_account.begin(), encrypt_account.end(), std::back_inserter(encrypt_account_hex));

    ofs << encrypt_userId_hex << std::endl;
    ofs << encrypt_username_hex << std::endl;
    ofs << encrypt_token_hex << std::endl;
    ofs << encrypt_time_hex << std::endl;
    ofs << encrypt_icon_hex << std::endl;
    ofs << encrypt_islogin_hex << std::endl;
    ofs << encrypt_account_hex << std::endl;
}

void SnapmakerWorld::check_write_task_queue(SnapmakerWorld* obj) {
    while (true) {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait(lock, [obj] { return !obj->m_write_task_queue.empty(); });

        GUI_App::SMUserInfo target = obj->m_write_task_queue.front();
        obj->m_write_task_queue.pop();
        lock.unlock();

        obj->write_userInfos(target);

        std::unique_lock<std::mutex> finish_lock(task_finish_mtx);
        lock.lock();
        if (obj->m_task_finish && obj->m_write_task_queue.empty()) {
            lock.unlock();
            finish_lock.unlock();
            break;
        }

        lock.unlock();
        finish_lock.unlock();
    }

}

void SnapmakerWorld::add_target(GUI_App::SMUserInfo& info) {
    std::unique_lock<std::mutex> lock(mtx);
    m_write_task_queue.push(info);
    cv.notify_one();
    lock.unlock();
}

} // GUI
} // Slic3r
