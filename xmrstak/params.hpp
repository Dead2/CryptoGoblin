#pragma once

#include "xmrstak/misc/environment.hpp"

#include <string>

namespace xmrstak
{

struct params
{

    static inline params& inst()
    {
        auto& env = environment::inst();
        if(env.pParams == nullptr)
            env.pParams = new params;
        return *env.pParams;
    }

    std::string executablePrefix;
    std::string binaryName;
    // user selected OpenCL vendor
    std::string openCLVendor;

    std::string poolURL;
    std::string poolPasswd;
    std::string poolRigid;
    std::string poolUsername;

    std::string currency;

    std::string configFile;
    std::string configFilePools;
    std::string configFileAMD;
    std::string configFileNVIDIA;
    std::string configFileCPU;

    std::string minerArg0;
    std::string minerArgs;

    static constexpr int32_t httpd_port_unset = -1;
    static constexpr int32_t httpd_port_disabled = 0;
    int32_t httpd_port = httpd_port_unset;

    // block_version >= 0 enable benchmark
    int benchmark_block_version = -1;
    int benchmark_wait_sec = 30;
    int benchmark_work_sec = 60;

    bool useAMD;
    bool AMDCache;
    bool useNVIDIA;
    bool useCPU;

    bool allowUAC = true;

    bool poolUseTls = false;
    bool userSetPwd = false;
    bool userSetRigid = false;
    bool nicehashMode = false;


    params() :
        executablePrefix(""),
        binaryName("xmr-stak"),
        openCLVendor("AMD"),
        configFile("config.txt"),
        configFilePools("pools.txt"),
        configFileAMD("amd.txt"),
        configFileNVIDIA("nvidia.txt"),
        configFileCPU("cpu.txt"),
        useAMD(true),
        AMDCache(true),
        useNVIDIA(true),
        useCPU(true)
    {}

};

} // namespace xmrstak
