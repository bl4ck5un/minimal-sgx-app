
// SGX headers
#include <sgx_uae_service.h>

// system headers
#include <grpcpp/server_builder.h>
#include <log4cxx/logger.h>
#include <log4cxx/propertyconfigurator.h>

#include <atomic>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <chrono>
#include <csignal>
#include <iostream>
#include <string>
#include <thread>
#include <utility>

// app headers
#include "App/Enclave_u.h"
#include "App/config.h"
#include "App/logging.h"
#include "App/rpc.h"
#include "App/utils.h"

namespace po = boost::program_options;
namespace fs = boost::filesystem;

using namespace std;

int main(int argc, const char *argv[])
{
  log4cxx::PropertyConfigurator::configure(LOGGING_CONF_FILE);
  log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("tc.cpp"));

  tc::Config config(argc, argv);
  LL_INFO("config:\n%s", config.toString().c_str());

  int ret;
  sgx_enclave_id_t eid;
  sgx_status_t st;

  ret = initialize_enclave(config.getEnclavePath().c_str(), &eid);
  if (ret != 0) {
    LL_CRITICAL("Failed to initialize the enclave");
    std::exit(-1);
  } else {
    LL_INFO("Enclave %ld created", eid);
  }

  // starting the backend RPC server
  RpcServer tc_service(eid);
  std::string server_address("0.0.0.0:" +
                             std::to_string(config.getRelayRPCAccessPoint()));
  grpc::ServerBuilder builder;
  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
  builder.RegisterService(&tc_service);

  std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
  LOG4CXX_INFO(logger, "TC service listening on " << server_address);

  server->Wait();
  sgx_destroy_enclave(eid);
  LL_INFO("all enclave closed successfully");
}
