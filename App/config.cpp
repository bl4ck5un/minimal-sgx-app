
#include "App/config.h"

#include <pwd.h>
#include <sys/types.h>

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <iostream>

using namespace std;

void tc::Config::parseConfigFile()
{
  // parse the config files
  boost::property_tree::ptree pt;
  try {
    boost::property_tree::ini_parser::read_ini(configFile, pt);
    enclavePath = pt.get<string>("enclave_path");
    tcContractEthereumAddr = pt.get<string>("tc_address");
    relayRPCAccessPoint = pt.get<int>("RPC.port");
    sealedECDSAKey = pt.get<string>("sealed.sig_key");
    sealedHybridEncryptionkey = pt.get<string>("sealed.hybrid_key");
  } catch (const exception &e) {
    cout << e.what() << endl;
    cout << "please provide with a correct config file" << endl;
    exit(-1);
  }
}

tc::Config::Config(int argc, const char **argv)
{
  try {
    po::options_description desc("Allowed options");
    desc.add_options()("help,h", "print this message");
    desc.add_options()("measurement,m",
                       po::bool_switch(&isPrintMR)->default_value(false),
                       "print the measurement (MR_ENCLAVE) and exit.");
    desc.add_options()("config,c",
                       po::value(&configFile)->default_value(DFT_CONFIG_FILE),
                       "Path to a config file");
    po::store(po::parse_command_line(argc, argv, desc), vm);

    if (vm.count("help")) {
      cerr << desc;
      cerr.flush();
      exit(0);
    }
    po::notify(vm);
  } catch (po::required_option &e) {
    cerr << e.what() << endl;
    exit(-1);
  } catch (exception &e) {
    cerr << e.what() << endl;
    exit(-1);
  } catch (...) {
    cerr << "Unknown error!" << endl;
    exit(-1);
  }

  parseConfigFile();
}

string tc::Config::toString()
{
  stringstream ss;
  ss << "Using config file: " << this->getConfigFile() << endl;
  ss << "+ using enclave image: " << this->getEnclavePath() << endl;
  ss << "+ listening for TC relay at port: " << this->getRelayRPCAccessPoint()
     << endl;
  ss << "+ serving contract at: " << this->getTcEthereumAddress();
  return ss.str();
}

const string &tc::Config::getConfigFile() const { return configFile; }
int tc::Config::getRelayRPCAccessPoint() const { return relayRPCAccessPoint; }
const string &tc::Config::getSealedSigKey() const { return sealedECDSAKey; }
const string &tc::Config::getSealedHybridKey() const
{
  return sealedHybridEncryptionkey;
}
const string &tc::Config::getEnclavePath() const { return enclavePath; }
const string &tc::Config::getTcEthereumAddress() const
{
  return tcContractEthereumAddr;
}
bool tc::Config::getIsPrintMR() const { return isPrintMR; }
