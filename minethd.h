#pragma once
#include <thread>
#include <atomic>
#include <mutex>
#include "crypto/cryptonight.h"

class telemetry
{
public:
    telemetry(size_t iThd);
    void push_perf_value(size_t iThd, uint64_t iHashCount, uint64_t iTimestamp);
    double calc_telemetry_data(size_t iLastMilisec, size_t iThread);

private:
    constexpr static size_t iBucketSize = 2 << 11; //Power of 2 to simplify calculations
    constexpr static size_t iBucketMask = iBucketSize - 1;
    uint32_t* iBucketTop;
    uint64_t** ppHashCounts;
    uint64_t** ppTimestamps;
};

class minethd
{
public:
    struct miner_work
    {
        char        sJobID[64];
        uint8_t     bWorkBlob[112];
        uint64_t    iTarget;
        size_t      iPoolId;
        uint32_t    iWorkSize;
        uint32_t    iResumeCnt;
        bool        bNiceHash;
        bool        bStall;

        miner_work() : iPoolId(0), iWorkSize(0), bStall(true) { }

        miner_work(const char* sJobID, const uint8_t* bWork, uint32_t iWorkSize, uint32_t iResumeCnt,
            uint64_t iTarget, bool bNiceHash, size_t iPoolId) :  iTarget(iTarget), iPoolId(iPoolId),
            iWorkSize(iWorkSize), iResumeCnt(iResumeCnt), bNiceHash(bNiceHash), bStall(false)
        {
            assert(iWorkSize <= sizeof(bWorkBlob));
            memcpy(this->sJobID, sJobID, sizeof(miner_work::sJobID));
            memcpy(this->bWorkBlob, bWork, iWorkSize);
        }

        miner_work(miner_work const&) = delete;

        miner_work& operator=(miner_work const& from)
        {
            assert(this != &from);

            iWorkSize = from.iWorkSize;
            iResumeCnt = from.iResumeCnt;
            iTarget = from.iTarget;
            iPoolId = from.iPoolId;
            bNiceHash = from.bNiceHash;
            bStall = from.bStall;

            assert(iWorkSize <= sizeof(bWorkBlob));
            memcpy(sJobID, from.sJobID, sizeof(sJobID));
            memcpy(bWorkBlob, from.bWorkBlob, iWorkSize);

            return *this;
        }

        miner_work(miner_work&& from) : iTarget(from.iTarget), iPoolId(from.iPoolId),
            iWorkSize(from.iWorkSize), bStall(from.bStall)
        {
            assert(iWorkSize <= sizeof(bWorkBlob));
            memcpy(sJobID, from.sJobID, sizeof(sJobID));
            memcpy(bWorkBlob, from.bWorkBlob, iWorkSize);
        }

        miner_work& operator=(miner_work&& from)
        {
            assert(this != &from);

            iWorkSize = from.iWorkSize;
            iResumeCnt = from.iResumeCnt;
            iTarget = from.iTarget;
            iPoolId = from.iPoolId;
            bNiceHash = from.bNiceHash;
            bStall = from.bStall;

            assert(iWorkSize <= sizeof(bWorkBlob));
            memcpy(sJobID, from.sJobID, sizeof(sJobID));
            memcpy(bWorkBlob, from.bWorkBlob, iWorkSize);

            return *this;
        }
    };

    static void switch_work(miner_work& pWork);
    static std::vector<minethd*>* thread_starter(miner_work& pWork);
    static bool self_test();

    std::atomic<uint64_t> iHashCount;
    std::atomic<uint64_t> iTimestamp;

private:
    typedef void (*cn_hash_fun)(const void*, size_t, void*, cryptonight_ctx*);
    typedef void (*cn_hash_fun_dbl)(const void*, size_t, void*, cryptonight_ctx* __restrict, cryptonight_ctx* __restrict);

    minethd(miner_work& pWork, size_t iNo, bool double_work, bool no_prefetch, int64_t affinity);

    // We use the top 10 bits of the nonce for thread and resume
    // This allows us to resume up to 128 threads 4 times before
    // we get nonce collisions
    // Bottom 22 bits allow for an hour of work at 1000 H/s
    inline uint32_t calc_start_nonce(uint32_t resume)
        { return (resume * iThreadCount + iThreadNo) << 22; }

    // Limited version of the nonce calc above
    inline uint32_t calc_nicehash_nonce(uint32_t start, uint32_t resume)
        { return start | (resume * iThreadCount + iThreadNo) << 18; }

    static cn_hash_fun func_selector(bool bHaveAes, bool bNoPrefetch);
    static cn_hash_fun_dbl func_dbl_selector(bool bHaveAes, bool bNoPrefetch);

    void work_main();
    void double_work_main();
    void consume_work();
    void pin_thd_affinity();
    uint32_t* prep_double_work(uint8_t bDoubleWorkBlob[sizeof(miner_work::bWorkBlob) * 2]);

    static std::atomic<uint64_t> iGlobalJobNo;
    static std::atomic<uint64_t> iConsumeCnt;
    static uint64_t iThreadCount;

    std::thread oWorkThd;
    // Held by the creating context to prevent a race cond with oWorkThd = std::thread(...)
    std::mutex work_thd_mtx;

    uint64_t iJobNo;
    int64_t affinity;
    uint8_t iThreadNo;

    bool bQuit;
    bool bNoPrefetch;

    miner_work oWork;
    static miner_work oGlobalWork;
};

