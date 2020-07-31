#ifndef TOWN_CRIER_RPC_H
#define TOWN_CRIER_RPC_H

#include <grpc/grpc.h>
#include <log4cxx/log4cxx.h>
#include <log4cxx/logger.h>
#include <sgx_eid.h>

#include <cstdio>

#include "services/generated/enclave.grpc.pb.h"
#include "services/generated/enclave.pb.h"

class RpcServer final : public rpc::enclave::Service
{
 private:
  log4cxx::LoggerPtr logger;
  sgx_enclave_id_t eid;

 public:
  explicit RpcServer(sgx_enclave_id_t eid)
      : logger(log4cxx::Logger::getLogger("RPC")), eid(eid)
  {
  }

  ::grpc::Status attest(::grpc::ServerContext* context,
                        const ::rpc::Empty* request,
                        ::rpc::Attestation* response) override;
  ::grpc::Status status(::grpc::ServerContext* context,
                        const ::rpc::Empty* request,
                        ::rpc::Status* response) override;
  ::grpc::Status process(::grpc::ServerContext* context,
                         const ::rpc::Request* request,
                         ::rpc::Response* response) override;
};

#endif  // TOWN_CRIER_RPC_H
