#include "rpc.h"

::grpc::Status RpcServer::attest(::grpc::ServerContext* context,
                                 const ::rpc::Empty* request,
                                 ::rpc::Attestation* response)
{
  return grpc::Status::OK;
}
::grpc::Status RpcServer::status(::grpc::ServerContext* context,
                                 const ::rpc::Empty* request,
                                 ::rpc::Status* response)
{
  return grpc::Status::OK;
}
::grpc::Status RpcServer::process(::grpc::ServerContext* context,
                                  const ::rpc::Request* request,
                                  ::rpc::Response* response)
{
  return grpc::Status::OK;
}
