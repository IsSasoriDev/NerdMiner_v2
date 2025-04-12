#include <Arduino.h>
#include <ArduinoJson.h>
#include <WiFi.h>
#include <esp_task_wdt.h>
#include <nvs_flash.h>
#include <nvs.h>
#include "ShaTests/nerdSHA256plus.h"
#include "stratum.h"
#include "mining.h"
#include "utils.h"
#include "monitor.h"
#include "timeconst.h"
#include "drivers/displays/display.h"
#include "drivers/storage/storage.h"

nvs_handle_t stat_handle;

uint32_t templates = 0;
uint32_t hashes = 0;
uint32_t Mhashes = 0;
uint32_t totalKHashes = 0;
uint32_t elapsedKHs = 0;
uint64_t upTime = 0;

uint32_t shares;
uint32_t valids;

double best_diff = 0.0;

extern TSettings Settings;

IPAddress serverIP(1, 1, 1, 1);

static WiFiClient client;
static miner_data mMiner;
mining_subscribe mWorker;
mining_job mJob;
monitor_data mMonitor;
bool isMinerSuscribed = false;
unsigned long mLastTXtoPool = millis();

int saveIntervals[7] = {5 * 60, 15 * 60, 30 * 60, 1 * 3600, 3 * 3600, 6 * 3600, 12 * 3600};
int saveIntervalsSize = sizeof(saveIntervals) / sizeof(saveIntervals[0]);
int currentIntervalIndex = 0;

bool checkPoolConnection(void) {
  if (client.connected()) {
    return true;
  }
  
  isMinerSuscribed = false;
  
  Serial.println("Client not connected, trying to connect..."); 
  
  if(serverIP == IPAddress(1, 1, 1, 1)) {
    WiFi.hostByName(Settings.PoolAddress.c_str(), serverIP);
    Serial.printf("Resolved DNS and saved ip: %s\n", serverIP.toString());
  }
  
  if (!client.connect(serverIP, Settings.PoolPort)) {
    Serial.println("Impossible to connect to: " + Settings.PoolAddress);
    WiFi.hostByName(Settings.PoolAddress.c_str(), serverIP);
    Serial.printf("Resolved DNS again: %s\n", serverIP.toString());
    vTaskDelay(1000 / portTICK_PERIOD_MS);
    return false;
  }
  return true;
}

unsigned long mStart0Hashrate = 0;
bool checkPoolInactivity(unsigned int keepAliveTime, unsigned long inactivityTime){ 
    unsigned long currentKHashes = (Mhashes*1000) + hashes/1000;
    unsigned long elapsedKHs = currentKHashes - totalKHashes;

    if(millis() - mLastTXtoPool > keepAliveTime){
      mLastTXtoPool = millis();
      Serial.println("Sending KeepAlive to pool");
      tx_suggest_difficulty(client, DEFAULT_DIFFICULTY);
    }

    if(elapsedKHs == 0){
      if(mStart0Hashrate == 0) mStart0Hashrate  = millis(); 
      if((millis()-mStart0Hashrate) > inactivityTime) { mStart0Hashrate=0; return true;}
      return false;
    }

  mStart0Hashrate = 0;
  return false;
}

void runStratumWorker(void *name) {
  Serial.println("");
  Serial.printf("\n[WORKER] Started. Running %s on core %d\n", (char *)name, xPortGetCoreID());

  double currentPoolDifficulty = DEFAULT_DIFFICULTY;

  while(true) {
    if(WiFi.status() != WL_CONNECTED){
      mMonitor.NerdStatus = NM_Connecting;
      WiFi.reconnect();
      vTaskDelay(5000 / portTICK_PERIOD_MS);
      continue;
    } 

    if(!checkPoolConnection()){
      srand(millis());
      vTaskDelay(((1 + rand() % 120) * 1000) / portTICK_PERIOD_MS);
    }

    if(!isMinerSuscribed){
      mMiner.inRun = false;
      mWorker = init_mining_subscribe();

      if(!tx_mining_subscribe(client, mWorker)) { 
        client.stop();
        continue; 
      }
      
      strcpy(mWorker.wName, Settings.BtcWallet);
      strcpy(mWorker.wPass, Settings.PoolPassword);
      tx_mining_auth(client, mWorker.wName, mWorker.wPass);
      tx_suggest_difficulty(client, DEFAULT_DIFFICULTY);

      isMinerSuscribed = true;
      mLastTXtoPool = millis();
    }

    if(checkPoolInactivity(KEEPALIVE_TIME_ms, POOLINACTIVITY_TIME_ms)){
      Serial.println("  Detected more than 2 min without data from pool. Closing socket and reopening...");
      client.stop();
      isMinerSuscribed = false;
      continue; 
    }

    while(client.connected() && client.available()){
      String line = client.readStringUntil('\n');
      stratum_method result = parse_mining_method(line);
      switch (result)
      {
          case STRATUM_PARSE_ERROR:   Serial.println("Parsed JSON: error on JSON"); break;
          case MINING_NOTIFY:         if(parse_mining_notify(line, mJob)){
                                          templates++;
                                          mMiner.inRun = false;
                                          mMiner = calculateMiningData(mWorker, mJob);
                                          mMiner.poolDifficulty = currentPoolDifficulty;
                                          mMiner.newJob = true;
                                          mMiner.newJob2 = true;
                                      }
                                      break;
          case MINING_SET_DIFFICULTY: parse_mining_set_difficulty(line, currentPoolDifficulty);
                                      mMiner.poolDifficulty = currentPoolDifficulty;
                                      break;
          case STRATUM_SUCCESS:       Serial.println("Parsed JSON: Success"); break;
          default:                    Serial.println("Parsed JSON: unknown"); break;
      }
    }

    vTaskDelay(500 / portTICK_PERIOD_MS); 
  }
}

void runMiner(void * task_id) {
  unsigned int miner_id = (uint32_t)task_id;
  Serial.printf("[MINER]  %d  Started runMiner Task!\n", miner_id);

  while(1){
    while(1){
      if(mMiner.newJob == true || mMiner.newJob2 == true) break;
      vTaskDelay(100 / portTICK_PERIOD_MS); 
    }
    vTaskDelay(10 / portTICK_PERIOD_MS); 

    if(mMiner.newJob) mMiner.newJob = false; 
    else if(mMiner.newJob2) mMiner.newJob2 = false;
    mMiner.inRun = true;

    nerdSHA256_context nerdMidstate;
    uint8_t hash[32];

    nerd_mids(&nerdMidstate, mMiner.bytearray_blockheader); 

    unsigned long nonce = TARGET_NONCE - MAX_NONCE;
    nonce += miner_id;
    uint32_t startT = micros();
    unsigned char *header64;

    memcpy(mMiner.bytearray_blockheader2, &mMiner.bytearray_blockheader, 80);
    if (miner_id == 0) header64 = mMiner.bytearray_blockheader + 64;
    else header64 = mMiner.bytearray_blockheader2 + 64;
    
    bool is16BitShare = true;  
    while(true) {
      if (miner_id == 0) memcpy(mMiner.bytearray_blockheader + 76, &nonce, 4);
      else memcpy(mMiner.bytearray_blockheader2 + 76, &nonce, 4);

      is16BitShare = nerd_sha256d(&nerdMidstate, header64, hash);

      hashes++;
      if (nonce > TARGET_NONCE) break; 

      if(!mMiner.inRun) { Serial.println ("MINER WORK ABORTED"); break;}

      if(hash[31] != 0 || hash[30] != 0) {
        nonce += 2;
        continue;
      }

      double diff_hash = diff_from_target(hash);

      if (diff_hash > best_diff) best_diff = diff_hash;

      if(diff_hash > mMiner.poolDifficulty){
        tx_mining_submit(client, mWorker, mJob, nonce);
        mLastTXtoPool = millis();  
      }

      if(hash[29] != 0 || hash[28] != 0) {
        nonce += 2;
        continue;
      }
      shares++;

      if(checkValid(hash, mMiner.bytearray_target)){
        valids++;
        break;
      }
      nonce += 2;
    }

    mMiner.inRun = false;

    if(hashes >= MAX_NONCE_STEP) {
      Mhashes = Mhashes + MAX_NONCE_STEP / 1000000;
      hashes = hashes - MAX_NONCE_STEP;
    }

    uint32_t duration = micros() - startT;
  }
}

#define DELAY 100
#define REDRAW_EVERY 10

void restoreStat() {
  if(!Settings.saveStats) return;
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    Serial.printf("[MONITOR] NVS partition is full or has invalid version, erasing...\n");
    nvs_flash_init();
  }

  ret = nvs_open("state", NVS_READWRITE, &stat_handle);

  size_t required_size = sizeof(double);
  nvs_get_blob(stat_handle, "best_diff", &best_diff, &required_size);
  nvs_get_u32(stat_handle, "Mhashes", &Mhashes);
  nvs_get_u32(stat_handle, "shares", &shares);
  nvs_get_u32(stat_handle, "valids", &valids);
  nvs_get_u32(stat_handle, "templates", &templates);
  nvs_get_u64(stat_handle, "upTime", &upTime);
}

void saveStat() {
  if(!Settings.saveStats) return;
  Serial.printf("[MONITOR] Saving stats\n");
  nvs_set_blob(stat_handle, "best_diff", &best_diff, sizeof(double));
  nvs_set_u32(stat_handle, "Mhashes", Mhashes);
  nvs_set_u32(stat_handle, "shares", shares);
  nvs_set_u32(stat_handle, "valids", valids);
  nvs_set_u32(stat_handle, "templates", templates);
  nvs_set_u64(stat_handle, "upTime", upTime + (esp_timer_get_time()/1000000));
}

void resetStat() {
    Serial.printf("[MONITOR] Resetting NVS stats\n");
    templates = hashes = Mhashes = totalKHashes = elapsedKHs = upTime = shares = valids = 0;
    best_diff = 0.0;
    saveStat();
}

void setup() {
  Serial.begin(115200);
  WiFi.begin(Settings.WifiSSID, Settings.WifiPassword);
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.println("Connecting to WiFi...");
  }

  restoreStat();

  Serial.printf("[MONITOR] WiFi Connected. IP: %s\n", WiFi.localIP().toString().c_str());

  xTaskCreate(runStratumWorker, "Run Stratum Worker", 8192, (void *)"worker", 1, NULL);
  xTaskCreate(runMiner, "Run Miner", 8192, (void *)0, 1, NULL);
}

void loop() {
  saveStat();
  delay(10000);
}
