R"===(
/*
 * Thread configuration for each thread. Make sure it matches the number above.
 * thread_mode -    1: Single mode is the normal mode.
 *                  2: Double mode will work on two blocks at the same time, but will require 2x the cache.
 *                  3: Triple mode will work on three blocks at the same time, but will require 3x the cache.
 *                  4: Quadruple mode will work on four blocks at the same time, but will require 4x the cache.
 *                  5: Pentuple mode will work on five blocks at the same time, but will require 5x the cache.
 *
 *                  Using one double thread instead of two single threads can save power, at the cost of ~15-20% hashrate.
 *
 * prefetch -       Some sytems can gain up to extra 5% here, but sometimes it will have no difference or make
 *                  things slower.
 *
 * affine_to_cpu -  This can be either false (no affinity), or the CPU core number. Note that on hyperthreading 
 *                  systems it is better to assign threads to physical cores. On Windows this usually means selecting 
 *                  even or odd numbered cpu numbers. For Linux it will be usually the lower CPU numbers, so for a 4 
 *                  physical core CPU you should select cpu numbers 0-3.
 *
 * On the first run the miner will look at your system and suggest a basic configuration that will work,
 * you can try to tweak it from there to get the best performance. Read TUNING.txt for more information.
 * 
 * A filled out configuration should look like this:
 * "cpu_threads_conf" :
 * [ 
 *      { "thread_mode" : 1, "prefetch" : true, "affine_to_cpu" : 0 },
 *      { "thread_mode" : 2, "prefetch" : true, "affine_to_cpu" : 1 },
 * ],
 *
 */

"cpu_threads_conf" :
[
CPUCONFIG
],

)==="
