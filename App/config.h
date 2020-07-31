#ifndef SRC_APP_CONFIG_H_
#define SRC_APP_CONFIG_H_

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <string>

using std::string;

namespace po = boost::program_options;
namespace fs = boost::filesystem;

namespace tc
{
class Config
{
 private:
  const string DFT_CONFIG_FILE = "/config";
  po::variables_map vm;

 public:
  const string &getConfigFile() const;
  int getRelayRPCAccessPoint() const;
  const string &getSealedSigKey() const;
  const string &getSealedHybridKey() const;
  const string &getEnclavePath() const;
  const string &getTcEthereumAddress() const;
  bool getIsPrintMR() const;

 private:
  bool isPrintMR;
  string configFile;
  int relayRPCAccessPoint;
  string tcContractEthereumAddr;
  string sealedECDSAKey;
  string sealedHybridEncryptionkey;
  string enclavePath;

  void parseConfigFile();

 public:
  Config(int argc, const char *argv[]);
  string toString();
};

}  // namespace tc

#endif  // SRC_APP_CONFIG_H_
