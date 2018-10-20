/*
  * This program is free software: you can redistribute it and/or modify
  * it under the terms of the GNU General Public License as published by
  * the Free Software Foundation, either version 3 of the License, or
  * any later version.
  *
  * This program is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  * GNU General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program.  If not, see <http://www.gnu.org/licenses/>.
  *
  * Additional permission under GNU GPL version 3 section 7
  *
  * If you modify this Program, or any covered work, by linking or combining
  * it with OpenSSL (or a modified version of that library), containing parts
  * covered by the terms of OpenSSL License and SSLeay License, the licensors
  * of this Program grant you additional permission to convey the resulting work.
  *
  */

#include "crypto/cryptonight_main_p.hpp"

#include "xmrstak/misc/console.hpp"
#include "xmrstak/cli/colors.hpp"
#include "xmrstak/backend/iBackend.hpp"
#include "xmrstak/backend/globalStates.hpp"
#include "xmrstak/misc/configEditor.hpp"
#include "xmrstak/backend/cpu/cpuType.hpp"
#include "xmrstak/params.hpp"
#include "jconf.hpp"

#include "xmrstak/misc/executor.hpp"
#include "minethd.hpp"
#include "xmrstak/jconf.hpp"

#include "hwlocMemory.hpp"
#include "xmrstak/backend/miner_work.hpp"

#ifndef CONF_NO_HWLOC
#   include "autoAdjustHwloc.hpp"
#else
#   include "autoAdjust.hpp"
#endif

#include <assert.h>
#include <cmath>
#include <chrono>
#include <cstring>
#include <thread>
#include <bitset>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>

#if defined(__APPLE__)
#include <mach/thread_policy.h>
#include <mach/thread_act.h>
#define SYSCTL_CORE_COUNT   "machdep.cpu.core_count"
#elif defined(__FreeBSD__)
#include <pthread_np.h>
#endif //__APPLE__

#endif //_WIN32

namespace xmrstak
{
namespace cpu
{

bool minethd::thd_setaffinity(std::thread::native_handle_type h, uint64_t cpu_id)
{
#if defined(_WIN32)
    // we can only pin up to 64 threads
    if(cpu_id < 64)	{
        #if defined(__MINGW32__)
            return SetThreadAffinityMask(GetCurrentThread(), 1ULL << cpu_id) != 0;
        #else
            return SetThreadAffinityMask(h, 1ULL << cpu_id) != 0;
        #endif
    } else {
        printer::inst()->print_msg(L0, "WARNING: Windows supports only affinity up to 63.");
        return false;
    }
#elif defined(__APPLE__)
    thread_port_t mach_thread;
    thread_affinity_policy_data_t policy = { static_cast<integer_t>(cpu_id) };
    mach_thread = pthread_mach_thread_np(h);
    return thread_policy_set(mach_thread, THREAD_AFFINITY_POLICY, (thread_policy_t)&policy, 1) == KERN_SUCCESS;
#elif defined(__FreeBSD__)
    cpuset_t mn;
    CPU_ZERO(&mn);
    CPU_SET(cpu_id, &mn);
    return pthread_setaffinity_np(h, sizeof(cpuset_t), &mn) == 0;
#elif defined(__OpenBSD__)
        printer::inst()->print_msg(L0,"WARNING: thread pinning is not supported under OPENBSD.");
        return true;
#else
    cpu_set_t mn;
    CPU_ZERO(&mn);
    CPU_SET(cpu_id, &mn);
    return pthread_setaffinity_np(h, sizeof(cpu_set_t), &mn) == 0;
#endif
}

minethd::minethd(miner_work& pWork, size_t iNo, int iMultiway, bool prefetch, int64_t affinity, const std::string& asm_version)
{
    this->backendType = iBackend::CPU;
    oWork = pWork;
    bQuit = 0;
    iThreadNo = (uint8_t)iNo;
    iJobNo = 0;
    bPrefetch = prefetch;
    this->affinity = affinity;
    asm_version_str = asm_version;

    std::unique_lock<std::mutex> lck(thd_aff_set);
    std::future<void> order_guard = order_fix.get_future();

    switch (iMultiway)
    {
    case 5:
        oWorkThd = std::thread(&minethd::penta_work_main, this);
        break;
    case 4:
        oWorkThd = std::thread(&minethd::quad_work_main, this);
        break;
    case 3:
        oWorkThd = std::thread(&minethd::triple_work_main, this);
        break;
    case 2:
        oWorkThd = std::thread(&minethd::double_work_main, this);
        break;
    case 1:
    default:
        oWorkThd = std::thread(&minethd::work_main, this);
        break;
    }

    order_guard.wait();

    if(affinity >= 0) //-1 means no affinity
        if(!thd_setaffinity(oWorkThd.native_handle(), affinity))
            printer::inst()->print_msg(L1, "WARNING setting affinity failed.");
}

cryptonight_ctx* minethd::minethd_alloc_ctx()
{
    cryptonight_ctx* ctx;
    alloc_msg msg = { 0 };

    switch (::jconf::inst()->GetSlowMemSetting())
    {
    case ::jconf::never_use:
        ctx = cryptonight_alloc_ctx(1, 1, &msg);
        if (ctx == NULL)
            printer::inst()->print_msg(L0, "MEMORY ALLOC FAILED: %s", msg.warning);
        return ctx;

    case ::jconf::no_mlck:
        ctx = cryptonight_alloc_ctx(1, 0, &msg);
        if (ctx == NULL)
            printer::inst()->print_msg(L0, "MEMORY ALLOC FAILED: %s", msg.warning);
        return ctx;

    case ::jconf::print_warning:
        ctx = cryptonight_alloc_ctx(1, 1, &msg);
        if (msg.warning != NULL)
            printer::inst()->print_msg(L0, "MEMORY ALLOC FAILED: %s", msg.warning);
        if (ctx == NULL)
            ctx = cryptonight_alloc_ctx(0, 0, NULL);
        return ctx;

    case ::jconf::always_use:
        return cryptonight_alloc_ctx(0, 0, NULL);

    case ::jconf::unknown_value:
        return NULL; //Shut up compiler
    }

    return nullptr; //Should never happen
}

static constexpr size_t MAX_N = 5;
bool minethd::self_test()
{
    alloc_msg msg = { 0 };
    size_t res;
    bool fatal = false;

    switch (::jconf::inst()->GetSlowMemSetting())
    {
    case ::jconf::never_use:
        res = cryptonight_init(1, 1, &msg);
        fatal = true;
        break;

    case ::jconf::no_mlck:
        res = cryptonight_init(1, 0, &msg);
        fatal = true;
        break;

    case ::jconf::print_warning:
        res = cryptonight_init(1, 1, &msg);
        break;

    case ::jconf::always_use:
        res = cryptonight_init(0, 0, &msg);
        break;

    case ::jconf::unknown_value:
    default:
        return false; //Shut up compiler
    }

    if(msg.warning != nullptr)
        printer::inst()->print_msg(L0, "MEMORY INIT ERROR: %s", msg.warning);

    if(res == 0 && fatal)
        return false;

    cryptonight_ctx *ctx[MAX_N] = {0};
    for (uint32_t i = 0; i < MAX_N; i++)
    {
        if ((ctx[i] = minethd_alloc_ctx()) == nullptr)
        {
            printer::inst()->print_msg(L0, "ERROR: miner was not able to allocate memory.");
            for (uint32_t j = 0; j < i; j++)
                cryptonight_free_ctx(ctx[j]);
            return false;
        }
    }

    bool bResult = true;
    xmrstak_algo algo = xmrstak_algo::invalid_algo;

    for(int algo_idx = 0; algo_idx < 2; ++algo_idx)
    {
        if(algo_idx == 0)
            algo = ::jconf::inst()->GetCurrentCoinSelection().GetDescription(1).GetMiningAlgo();
        else
            algo = ::jconf::inst()->GetCurrentCoinSelection().GetDescription(1).GetMiningAlgoRoot();

        // New-style testing
        bResult = bResult && testrunner<1>(algo, ctx);
        bResult = bResult && testrunner<2>(algo, ctx);
        bResult = bResult && testrunner<3>(algo, ctx);
        bResult = bResult && testrunner<4>(algo, ctx);
        bResult = bResult && testrunner<5>(algo, ctx);
    }

    for (uint32_t i = 0; i < MAX_N; i++)
        cryptonight_free_ctx(ctx[i]);

    if (bResult){
        printer::inst()->print_msg(L0, "Cryptonight hash self-test successful.");
    }

    return bResult;
}

struct testVal {
    const char* testString;
    const char* testResult;
    uint32_t    resultLen;
    xmrstak_algo algo;
};

testVal oTestValues[] = {
    { "This is a test This is a test This is a test", "\x35\x3f\xdc\x06\x8f\xd4\x7b\x03\xc0\x4b\x94\x31\xe0\x05\xe0\x0b\x68\xc2\x16\x8a\x3c\xc7\x33\x5c\x8b\x9b\x30\x81\x56\x59\x1a\x4f", 32, cryptonight_monero_v8 },
#ifndef ONLY_XMR_ALGO
    { "This is a test", "\xa0\x84\xf0\x1d\x14\x37\xa0\x9c\x69\x85\x40\x1b\x60\xd4\x35\x54\xae\x10\x58\x02\xc5\xf5\xd8\xa9\xb3\x25\x36\x49\xc0\xbe\x66\x05", 32, cryptonight },
    { "This is a test This is a test This is a test", "\x1\x57\xc5\xee\x18\x8b\xbe\xc8\x97\x52\x85\xa3\x6\x4e\xe9\x20\x65\x21\x76\x72\xfd\x69\xa1\xae\xbd\x7\x66\xc7\xb5\x6e\xe0\xbd", 32, cryptonight_monero },
    { "This is a test This is a test This is a test", "\x5a\x24\xa0\x29\xde\x1c\x39\x3f\x3d\x52\x7a\x2f\x9b\x39\xdc\x3d\xb3\xbc\x87\x11\x8b\x84\x52\x9b\x9f\x0\x88\x49\x25\x4b\x5\xce", 32, cryptonight_lite },
    { "This is a test This is a test This is a test", "\xfc\xa1\x7d\x44\x37\x70\x9b\x4a\x3b\xd7\x1e\xf3\xed\x21\xb4\x17\xca\x93\xdc\x86\x79\xce\x81\xdf\xd3\xcb\xdd\xa\x22\xd7\x58\xba", 32, cryptonight_aeon },
    { "This is a test This is a test This is a test", "\xbc\xe7\x48\xaf\xc5\x31\xff\xc9\x33\x7f\xcf\x51\x1b\xe3\x20\xa3\xaa\x8d\x4\x55\xf9\x14\x2a\x61\xe8\x38\xdf\xdc\x3b\x28\x3e\x0", 32, cryptonight_ipbc },
    { "This is a test This is a test This is a test", "\xb9\x9d\x6c\xee\x50\x3c\x6f\xa6\x3f\x30\x69\x24\x4a\x0\x9f\xe4\xd4\x69\x3f\x68\x92\xa4\x5c\xc2\x51\xae\x46\x87\x7c\x6b\x98\xae", 32, cryptonight_stellite },
    { "This is a test This is a test This is a test", "\xf9\x44\x97\xce\xb4\xf0\xd9\x84\xb\x9b\xfc\x45\x94\x74\x55\x25\xcf\x26\x83\x16\x4f\xc\xf8\x2d\xf5\xf\x25\xff\x45\x28\x2e\x85", 32, cryptonight_heavy },
#endif
};

constexpr uint32_t iSelftestCnt = (sizeof(oTestValues)/sizeof(oTestValues[0]));

testVal getSelftestValues(xmrstak_algo algo){
    for(uint32_t testnum = 0; testnum <= iSelftestCnt; testnum++){
        testVal current = oTestValues[testnum];
        if(current.algo == algo){
            return current;
        }
    }
}

void printhex(const char *label, char *buffer, uint16_t len){
    printf(label);
    for(uint16_t i=0 ; i <= (len - 1); i++){
        printf("\\x%02x", (unsigned char)buffer[i]);
    }
    printf("\n");
}

template<uint8_t MULTIPLE>
bool minethd::testrunner(xmrstak_algo algo, cryptonight_ctx **ctx){
    testVal currTest = getSelftestValues(algo);
    cn_hash_fun hashf;
    unsigned char out[32 * MULTIPLE];

    uint16_t testStringLen = strlen(currTest.testString);
    uint16_t testResultLen = currTest.resultLen * MULTIPLE;
    char testString[(testStringLen * MULTIPLE) +1];
    char testResult[testResultLen +1];
    testString[0] = '\0';
    testResult[0] = '\0';

    for (uint8_t i = 0; i < MULTIPLE; i++){
        strcat(testString, currTest.testString);
        strcat(testResult, currTest.testResult);
    }

    // Without prefetch
    hashf = func_multi_selector<MULTIPLE>(::jconf::inst()->HaveHardwareAes(), false, algo);
    hashf(testString, testStringLen, out, ctx);
    bool bResult = memcmp(out, testResult, testResultLen) == 0;

    // With prefetch
    hashf = func_multi_selector<MULTIPLE>(::jconf::inst()->HaveHardwareAes(), true, algo);
    hashf(testString, testStringLen, out, ctx);
    bResult = bResult &&  memcmp(out, testResult, testResultLen) == 0;

    if (!bResult){
        printer::inst()->print_msg(L0, "Hash self-test failed. This might be caused by bad compiler optimizations.", testString);
        printhex("Correct: ", testResult, testResultLen);
        printhex("Result:  ", (char*)out, testResultLen);
    }

    return bResult;
}

std::vector<iBackend*> minethd::thread_starter(uint32_t threadOffset, miner_work& pWork)
{
    std::vector<iBackend*> pvThreads;

    if(!configEditor::file_exist(params::inst().configFileCPU))
    {
        autoAdjust adjust;
        if(!adjust.printConfig())
            return pvThreads;
    }

    if(!jconf::inst()->parse_config())
    {
        win_exit();
    }


    //Launch the requested number of single and double threads, to distribute
    //load evenly we need to alternate single and double threads
    size_t i, n = jconf::inst()->GetThreadCount();
    pvThreads.reserve(n);

    jconf::thd_cfg cfg;
    for (i = 0; i < n; i++)
    {
        jconf::inst()->GetThreadConfig(i, cfg);

        if(cfg.iCpuAff >= 0)
        {
#if defined(__APPLE__)
            printer::inst()->print_msg(L1, "WARNING on macOS thread affinity is only advisory.");
#endif

            printer::inst()->print_msg(L1, "Starting %dx thread, affinity: %d.", cfg.iMultiway, (int)cfg.iCpuAff);
        }
        else
            printer::inst()->print_msg(L1, "Starting %dx thread, no affinity.", cfg.iMultiway);

        minethd* thd = new minethd(pWork, i + threadOffset, cfg.iMultiway, cfg.bPrefetch, cfg.iCpuAff, cfg.asm_version_str);
        pvThreads.push_back(thd);
    }

    return pvThreads;
}

/** get the supported asm name
 *
 * @return asm type based on the number of hashes per thread the internal
 *             evaluated cpu type
 */
static std::string getAsmName(const uint32_t num_hashes)
{
    std::string asm_type = "off";
    if(num_hashes != 0)
    {
    auto cpu_model = getModel();

    if(cpu_model.avx && cpu_model.aes)
            {
        if(cpu_model.type_name.find("Intel") != std::string::npos)
            asm_type = "intel_avx";
        else if(cpu_model.type_name.find("AMD") != std::string::npos && num_hashes == 1)
            asm_type = "amd_avx";
    }
    }
    return asm_type;
}

template<size_t N>
minethd::cn_hash_fun minethd::func_multi_selector(bool bHaveAes, bool bPrefetch, xmrstak_algo algo, const std::string& asm_version_str)
{
    static_assert(N >= 1, "number of threads must be >= 1" );

    // We have two independent flag bits in the functions
    // therefore we will build a binary digit and select the
    // function as a two digit binary

    uint8_t algv;
    switch(algo)
    {
    case cryptonight_monero_v8:
        algv = 0;
        break;
#ifndef ONLY_XMR_ALGO
    case cryptonight_monero:
        algv = 1;
        break;
    case cryptonight_lite:
        algv = 2;
        break;
    case cryptonight:
        algv = 3;
        break;
    case cryptonight_heavy:
        algv = 4;
        break;
    case cryptonight_aeon:
        algv = 5;
        break;
    case cryptonight_ipbc:
        algv = 6;
        break;
    case cryptonight_stellite:
        algv = 7;
        break;
#endif
    default:
        algv = 0;
        printer::inst()->print_msg(L0, RED("Unsupported algorithm selected, miner was only compiled with XMR support."));
        break;
    }

    static const cn_hash_fun func_table[] = {
        Cryptonight_hash<N>::template hash<cryptonight_monero_v8, false, false>,
        Cryptonight_hash<N>::template hash<cryptonight_monero_v8, true, false>,
        Cryptonight_hash<N>::template hash<cryptonight_monero_v8, false, true>,
        Cryptonight_hash<N>::template hash<cryptonight_monero_v8, true, true>,

#ifndef ONLY_XMR_ALGO
        Cryptonight_hash<N>::template hash<cryptonight_monero, false, false>,
        Cryptonight_hash<N>::template hash<cryptonight_monero, true, false>,
        Cryptonight_hash<N>::template hash<cryptonight_monero, false, true>,
        Cryptonight_hash<N>::template hash<cryptonight_monero, true, true>,

        Cryptonight_hash<N>::template hash<cryptonight_lite, false, false>,
        Cryptonight_hash<N>::template hash<cryptonight_lite, true, false>,
        Cryptonight_hash<N>::template hash<cryptonight_lite, false, true>,
        Cryptonight_hash<N>::template hash<cryptonight_lite, true, true>,

        Cryptonight_hash<N>::template hash<cryptonight, false, false>,
        Cryptonight_hash<N>::template hash<cryptonight, true, false>,
        Cryptonight_hash<N>::template hash<cryptonight, false, true>,
        Cryptonight_hash<N>::template hash<cryptonight, true, true>,

        Cryptonight_hash<N>::template hash<cryptonight_heavy, false, false>,
        Cryptonight_hash<N>::template hash<cryptonight_heavy, true, false>,
        Cryptonight_hash<N>::template hash<cryptonight_heavy, false, true>,
        Cryptonight_hash<N>::template hash<cryptonight_heavy, true, true>,

        Cryptonight_hash<N>::template hash<cryptonight_aeon, false, false>,
        Cryptonight_hash<N>::template hash<cryptonight_aeon, true, false>,
        Cryptonight_hash<N>::template hash<cryptonight_aeon, false, true>,
        Cryptonight_hash<N>::template hash<cryptonight_aeon, true, true>,

        Cryptonight_hash<N>::template hash<cryptonight_ipbc, false, false>,
        Cryptonight_hash<N>::template hash<cryptonight_ipbc, true, false>,
        Cryptonight_hash<N>::template hash<cryptonight_ipbc, false, true>,
        Cryptonight_hash<N>::template hash<cryptonight_ipbc, true, true>,

        Cryptonight_hash<N>::template hash<cryptonight_stellite, false, false>,
        Cryptonight_hash<N>::template hash<cryptonight_stellite, true, false>,
        Cryptonight_hash<N>::template hash<cryptonight_stellite, false, true>,
        Cryptonight_hash<N>::template hash<cryptonight_stellite, true, true>,
#endif
    };

    std::bitset<2> digit;
    digit.set(0, !bHaveAes);
    digit.set(1, bPrefetch);

    auto selected_function = func_table[ algv << 2 | digit.to_ulong() ];


        // check for asm optimized version for cryptonight_v8
        if(N <= 2 && algo == cryptonight_monero_v8 && bHaveAes)
        {
                std::string selected_asm = asm_version_str;
                if(selected_asm == "auto")
                        selected_asm = cpu::getAsmName(N);

                if(selected_asm != "off")
                {
                        if(selected_asm == "intel_avx")
                        {
                                // Intel Ivy Bridge (Xeon v2, Core i7/i5/i3 3xxx, Pentium G2xxx, Celeron G1xxx)
                                if(N == 1)
                                        selected_function = Cryptonight_hash_asm<1u, 0u>::template hash<cryptonight_monero_v8>;
                                else if(N == 2)
                                        selected_function = Cryptonight_hash_asm<2u, 0u>::template hash<cryptonight_monero_v8>;
                        }
                        // supports only 1 thread per hash
                        if(N == 1 && selected_asm == "amd_avx")
                        {
                                // AMD Ryzen (1xxx and 2xxx series)
                                selected_function = Cryptonight_hash_asm<1u, 1u>::template hash<cryptonight_monero_v8>;
                        }
                        if(asm_version_str == "auto" && (selected_asm != "intel_avx" || selected_asm != "amd_avx"))
                                printer::inst()->print_msg(L3, "Switch to assembler version for '%s' cpu's", selected_asm.c_str());
            else if(selected_asm != "intel_avx" && selected_asm != "amd_avx") // unknown asm type
                                printer::inst()->print_msg(L1, "Assembler '%s' unknown, fallback to non asm version of cryptonight_v8", selected_asm.c_str());
                }
        }

    return selected_function;
}

minethd::cn_hash_fun minethd::func_selector(bool bHaveAes, bool bPrefetch, xmrstak_algo algo)
{
    return func_multi_selector<1>(bHaveAes, bPrefetch, algo);
}

void minethd::work_main()
{
    multiway_work_main<1u>();
}

void minethd::double_work_main()
{
    multiway_work_main<2u>();
}

void minethd::triple_work_main()
{
    multiway_work_main<3u>();
}

void minethd::quad_work_main()
{
    multiway_work_main<4u>();
}

void minethd::penta_work_main()
{
    multiway_work_main<5u>();
}

template<size_t N>
void minethd::prep_multiway_work(uint8_t *bWorkBlob, uint32_t **piNonce)
{
    for (size_t i = 0; i < N; i++)
    {
        memcpy(bWorkBlob + oWork.iWorkSize * i, oWork.bWorkBlob, oWork.iWorkSize);
        if (i > 0)
            piNonce[i] = (uint32_t*)(bWorkBlob + oWork.iWorkSize * i + 39);
    }
}

template<uint32_t N>
void minethd::multiway_work_main()
{
    #if defined(BINDNUMAMEM)
    if(affinity >= 0) //-1 means no affinity
        bindMemoryToNUMANode(affinity);
    #endif

    order_fix.set_value();
    std::unique_lock<std::mutex> lck(thd_aff_set);
    lck.release();
    std::this_thread::yield();

    cryptonight_ctx *ctx[MAX_N];
    uint64_t iCount = 0;
    uint64_t *piHashVal[MAX_N];
    uint32_t *piNonce[MAX_N];
    uint8_t bHashOut[MAX_N * 32];
    uint8_t bWorkBlob[sizeof(miner_work::bWorkBlob) * MAX_N];
    uint32_t iNonce = 0;
    job_result res;

    for (size_t i = 0; i < N; i++)
    {
        ctx[i] = minethd_alloc_ctx();
        if(ctx[i] == nullptr)
        {
            printer::inst()->print_msg(L0, "ERROR: miner was not able to allocate memory.");
            for (uint32_t j = 0; j < i; j++)
                cryptonight_free_ctx(ctx[j]);
            win_exit(1);
        }
        piHashVal[i] = (uint64_t*)(bHashOut + 32 * i + 24);
        piNonce[i] = (i == 0) ? (uint32_t*)(bWorkBlob + 39) : nullptr;
    }

    if(!oWork.bStall)
        prep_multiway_work<N>(bWorkBlob, piNonce);

    globalStates::inst().iConsumeCnt++;

    // start with root algorithm and switch later if fork version is reached
    auto miner_algo = ::jconf::inst()->GetCurrentCoinSelection().GetDescription(1).GetMiningAlgoRoot();
    cn_hash_fun hash_fun_multi = func_multi_selector<N>(::jconf::inst()->HaveHardwareAes(), bPrefetch, miner_algo, asm_version_str);
    uint8_t version = 0;
    size_t lastPoolId = 0;

    while (bQuit == 0)
    {
        if (oWork.bStall)
        {
            /*	We are stalled here because the executor didn't find a job for us yet,
            either because of network latency, or a socket problem. Since we are
            raison d'etre of this software it us sensible to just wait until we have something*/

            while (globalStates::inst().iGlobalJobNo.load(std::memory_order_relaxed) == iJobNo)
                std::this_thread::sleep_for(std::chrono::milliseconds(1));

            globalStates::inst().consume_work(oWork, iJobNo);
            prep_multiway_work<N>(bWorkBlob, piNonce);
            continue;
        }

        constexpr uint32_t nonce_chunk = 4096;
        int64_t nonce_ctr = 0;

        assert(sizeof(job_result::sJobID) == sizeof(pool_job::sJobID));

        if(oWork.bNiceHash)
            iNonce = *piNonce[0];

        uint8_t new_version = oWork.getVersion();
        if(new_version != version || oWork.iPoolId != lastPoolId)
        {
            coinDescription coinDesc = ::jconf::inst()->GetCurrentCoinSelection().GetDescription(oWork.iPoolId);
            if(new_version >= coinDesc.GetMiningForkVersion())
            {
                miner_algo = coinDesc.GetMiningAlgo();
                hash_fun_multi = func_multi_selector<N>(::jconf::inst()->HaveHardwareAes(), bPrefetch, miner_algo, asm_version_str);
            }
            else
            {
                miner_algo = coinDesc.GetMiningAlgoRoot();
                hash_fun_multi = func_multi_selector<N>(::jconf::inst()->HaveHardwareAes(), bPrefetch, miner_algo, asm_version_str);
            }
            lastPoolId = oWork.iPoolId;
            version = new_version;
        }

        while (globalStates::inst().iGlobalJobNo.load(std::memory_order_relaxed) == iJobNo)
        {
            if ((iCount++ & 0xF) == 0)  //Store stats every 16*N hashes
            {
                uint64_t iStamp = get_timestamp_ms();
                iHashCount.store(iCount * N, std::memory_order_relaxed);
                iTimestamp.store(iStamp, std::memory_order_relaxed);
            }

            nonce_ctr -= N;
            if(nonce_ctr <= 0)
            {
                globalStates::inst().calc_start_nonce(iNonce, oWork.bNiceHash, nonce_chunk);
                nonce_ctr = nonce_chunk;
                // check if the job is still valid, there is a small posibility that the job is switched
                if(globalStates::inst().iGlobalJobNo.load(std::memory_order_relaxed) != iJobNo)
                    break;
            }

            for (size_t i = 0; i < N; i++)
                *piNonce[i] = iNonce++;

            hash_fun_multi(bWorkBlob, oWork.iWorkSize, bHashOut, ctx);

            for (size_t i = 0; i < N; i++)
            {
                if (*piHashVal[i] < oWork.iTarget)
                {
                    executor::inst()->push_event(
                        ex_event(job_result(oWork.sJobID, iNonce - N + i, bHashOut + 32 * i, iThreadNo, miner_algo),
                        oWork.iPoolId)
                    );
                }
            }

            std::this_thread::yield();
        }

        globalStates::inst().consume_work(oWork, iJobNo);
        prep_multiway_work<N>(bWorkBlob, piNonce);
    }
    for (uint32_t i = 0; i < N; i++)
        cryptonight_free_ctx(ctx[i]);
}

} // namespace cpu
} // namespace xmrstak
