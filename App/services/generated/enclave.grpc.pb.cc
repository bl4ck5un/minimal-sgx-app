// Generated by the gRPC C++ plugin.
// If you make any local change, they will be lost.
// source: enclave.proto

#include "enclave.grpc.pb.h"

#include <grpcpp/impl/codegen/async_stream.h>
#include <grpcpp/impl/codegen/async_unary_call.h>
#include <grpcpp/impl/codegen/channel_interface.h>
#include <grpcpp/impl/codegen/client_callback.h>
#include <grpcpp/impl/codegen/client_unary_call.h>
#include <grpcpp/impl/codegen/message_allocator.h>
#include <grpcpp/impl/codegen/method_handler.h>
#include <grpcpp/impl/codegen/rpc_service_method.h>
#include <grpcpp/impl/codegen/server_callback.h>
#include <grpcpp/impl/codegen/server_callback_handlers.h>
#include <grpcpp/impl/codegen/server_context.h>
#include <grpcpp/impl/codegen/service_type.h>
#include <grpcpp/impl/codegen/sync_stream.h>

#include <functional>

#include "enclave.pb.h"
namespace rpc
{
static const char* enclave_method_names[] = {
    "/rpc.enclave/attest",
    "/rpc.enclave/status",
    "/rpc.enclave/process",
};

std::unique_ptr<enclave::Stub> enclave::NewStub(
    const std::shared_ptr< ::grpc::ChannelInterface>& channel,
    const ::grpc::StubOptions& options)
{
  (void)options;
  std::unique_ptr<enclave::Stub> stub(new enclave::Stub(channel));
  return stub;
}

enclave::Stub::Stub(const std::shared_ptr< ::grpc::ChannelInterface>& channel)
    : channel_(channel),
      rpcmethod_attest_(enclave_method_names[0],
                        ::grpc::internal::RpcMethod::NORMAL_RPC,
                        channel),
      rpcmethod_status_(enclave_method_names[1],
                        ::grpc::internal::RpcMethod::NORMAL_RPC,
                        channel),
      rpcmethod_process_(enclave_method_names[2],
                         ::grpc::internal::RpcMethod::NORMAL_RPC,
                         channel)
{
}

::grpc::Status enclave::Stub::attest(::grpc::ClientContext* context,
                                     const ::rpc::Empty& request,
                                     ::rpc::Attestation* response)
{
  return ::grpc::internal::BlockingUnaryCall(
      channel_.get(), rpcmethod_attest_, context, request, response);
}

void enclave::Stub::experimental_async::attest(
    ::grpc::ClientContext* context,
    const ::rpc::Empty* request,
    ::rpc::Attestation* response,
    std::function<void(::grpc::Status)> f)
{
  ::grpc_impl::internal::CallbackUnaryCall(stub_->channel_.get(),
                                           stub_->rpcmethod_attest_,
                                           context,
                                           request,
                                           response,
                                           std::move(f));
}

void enclave::Stub::experimental_async::attest(
    ::grpc::ClientContext* context,
    const ::grpc::ByteBuffer* request,
    ::rpc::Attestation* response,
    std::function<void(::grpc::Status)> f)
{
  ::grpc_impl::internal::CallbackUnaryCall(stub_->channel_.get(),
                                           stub_->rpcmethod_attest_,
                                           context,
                                           request,
                                           response,
                                           std::move(f));
}

void enclave::Stub::experimental_async::attest(
    ::grpc::ClientContext* context,
    const ::rpc::Empty* request,
    ::rpc::Attestation* response,
    ::grpc::experimental::ClientUnaryReactor* reactor)
{
  ::grpc_impl::internal::ClientCallbackUnaryFactory::Create(
      stub_->channel_.get(),
      stub_->rpcmethod_attest_,
      context,
      request,
      response,
      reactor);
}

void enclave::Stub::experimental_async::attest(
    ::grpc::ClientContext* context,
    const ::grpc::ByteBuffer* request,
    ::rpc::Attestation* response,
    ::grpc::experimental::ClientUnaryReactor* reactor)
{
  ::grpc_impl::internal::ClientCallbackUnaryFactory::Create(
      stub_->channel_.get(),
      stub_->rpcmethod_attest_,
      context,
      request,
      response,
      reactor);
}

::grpc::ClientAsyncResponseReader< ::rpc::Attestation>*
enclave::Stub::AsyncattestRaw(::grpc::ClientContext* context,
                              const ::rpc::Empty& request,
                              ::grpc::CompletionQueue* cq)
{
  return ::grpc_impl::internal::
      ClientAsyncResponseReaderFactory< ::rpc::Attestation>::Create(
          channel_.get(), cq, rpcmethod_attest_, context, request, true);
}

::grpc::ClientAsyncResponseReader< ::rpc::Attestation>*
enclave::Stub::PrepareAsyncattestRaw(::grpc::ClientContext* context,
                                     const ::rpc::Empty& request,
                                     ::grpc::CompletionQueue* cq)
{
  return ::grpc_impl::internal::
      ClientAsyncResponseReaderFactory< ::rpc::Attestation>::Create(
          channel_.get(), cq, rpcmethod_attest_, context, request, false);
}

::grpc::Status enclave::Stub::status(::grpc::ClientContext* context,
                                     const ::rpc::Empty& request,
                                     ::rpc::Status* response)
{
  return ::grpc::internal::BlockingUnaryCall(
      channel_.get(), rpcmethod_status_, context, request, response);
}

void enclave::Stub::experimental_async::status(
    ::grpc::ClientContext* context,
    const ::rpc::Empty* request,
    ::rpc::Status* response,
    std::function<void(::grpc::Status)> f)
{
  ::grpc_impl::internal::CallbackUnaryCall(stub_->channel_.get(),
                                           stub_->rpcmethod_status_,
                                           context,
                                           request,
                                           response,
                                           std::move(f));
}

void enclave::Stub::experimental_async::status(
    ::grpc::ClientContext* context,
    const ::grpc::ByteBuffer* request,
    ::rpc::Status* response,
    std::function<void(::grpc::Status)> f)
{
  ::grpc_impl::internal::CallbackUnaryCall(stub_->channel_.get(),
                                           stub_->rpcmethod_status_,
                                           context,
                                           request,
                                           response,
                                           std::move(f));
}

void enclave::Stub::experimental_async::status(
    ::grpc::ClientContext* context,
    const ::rpc::Empty* request,
    ::rpc::Status* response,
    ::grpc::experimental::ClientUnaryReactor* reactor)
{
  ::grpc_impl::internal::ClientCallbackUnaryFactory::Create(
      stub_->channel_.get(),
      stub_->rpcmethod_status_,
      context,
      request,
      response,
      reactor);
}

void enclave::Stub::experimental_async::status(
    ::grpc::ClientContext* context,
    const ::grpc::ByteBuffer* request,
    ::rpc::Status* response,
    ::grpc::experimental::ClientUnaryReactor* reactor)
{
  ::grpc_impl::internal::ClientCallbackUnaryFactory::Create(
      stub_->channel_.get(),
      stub_->rpcmethod_status_,
      context,
      request,
      response,
      reactor);
}

::grpc::ClientAsyncResponseReader< ::rpc::Status>*
enclave::Stub::AsyncstatusRaw(::grpc::ClientContext* context,
                              const ::rpc::Empty& request,
                              ::grpc::CompletionQueue* cq)
{
  return ::grpc_impl::internal::
      ClientAsyncResponseReaderFactory< ::rpc::Status>::Create(
          channel_.get(), cq, rpcmethod_status_, context, request, true);
}

::grpc::ClientAsyncResponseReader< ::rpc::Status>*
enclave::Stub::PrepareAsyncstatusRaw(::grpc::ClientContext* context,
                                     const ::rpc::Empty& request,
                                     ::grpc::CompletionQueue* cq)
{
  return ::grpc_impl::internal::
      ClientAsyncResponseReaderFactory< ::rpc::Status>::Create(
          channel_.get(), cq, rpcmethod_status_, context, request, false);
}

::grpc::Status enclave::Stub::process(::grpc::ClientContext* context,
                                      const ::rpc::Request& request,
                                      ::rpc::Response* response)
{
  return ::grpc::internal::BlockingUnaryCall(
      channel_.get(), rpcmethod_process_, context, request, response);
}

void enclave::Stub::experimental_async::process(
    ::grpc::ClientContext* context,
    const ::rpc::Request* request,
    ::rpc::Response* response,
    std::function<void(::grpc::Status)> f)
{
  ::grpc_impl::internal::CallbackUnaryCall(stub_->channel_.get(),
                                           stub_->rpcmethod_process_,
                                           context,
                                           request,
                                           response,
                                           std::move(f));
}

void enclave::Stub::experimental_async::process(
    ::grpc::ClientContext* context,
    const ::grpc::ByteBuffer* request,
    ::rpc::Response* response,
    std::function<void(::grpc::Status)> f)
{
  ::grpc_impl::internal::CallbackUnaryCall(stub_->channel_.get(),
                                           stub_->rpcmethod_process_,
                                           context,
                                           request,
                                           response,
                                           std::move(f));
}

void enclave::Stub::experimental_async::process(
    ::grpc::ClientContext* context,
    const ::rpc::Request* request,
    ::rpc::Response* response,
    ::grpc::experimental::ClientUnaryReactor* reactor)
{
  ::grpc_impl::internal::ClientCallbackUnaryFactory::Create(
      stub_->channel_.get(),
      stub_->rpcmethod_process_,
      context,
      request,
      response,
      reactor);
}

void enclave::Stub::experimental_async::process(
    ::grpc::ClientContext* context,
    const ::grpc::ByteBuffer* request,
    ::rpc::Response* response,
    ::grpc::experimental::ClientUnaryReactor* reactor)
{
  ::grpc_impl::internal::ClientCallbackUnaryFactory::Create(
      stub_->channel_.get(),
      stub_->rpcmethod_process_,
      context,
      request,
      response,
      reactor);
}

::grpc::ClientAsyncResponseReader< ::rpc::Response>*
enclave::Stub::AsyncprocessRaw(::grpc::ClientContext* context,
                               const ::rpc::Request& request,
                               ::grpc::CompletionQueue* cq)
{
  return ::grpc_impl::internal::
      ClientAsyncResponseReaderFactory< ::rpc::Response>::Create(
          channel_.get(), cq, rpcmethod_process_, context, request, true);
}

::grpc::ClientAsyncResponseReader< ::rpc::Response>*
enclave::Stub::PrepareAsyncprocessRaw(::grpc::ClientContext* context,
                                      const ::rpc::Request& request,
                                      ::grpc::CompletionQueue* cq)
{
  return ::grpc_impl::internal::
      ClientAsyncResponseReaderFactory< ::rpc::Response>::Create(
          channel_.get(), cq, rpcmethod_process_, context, request, false);
}

enclave::Service::Service()
{
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      enclave_method_names[0],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::
          RpcMethodHandler<enclave::Service, ::rpc::Empty, ::rpc::Attestation>(
              [](enclave::Service* service,
                 ::grpc_impl::ServerContext* ctx,
                 const ::rpc::Empty* req,
                 ::rpc::Attestation* resp) {
                return service->attest(ctx, req, resp);
              },
              this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      enclave_method_names[1],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler<enclave::Service,
                                             ::rpc::Empty,
                                             ::rpc::Status>(
          [](enclave::Service* service,
             ::grpc_impl::ServerContext* ctx,
             const ::rpc::Empty* req,
             ::rpc::Status* resp) { return service->status(ctx, req, resp); },
          this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      enclave_method_names[2],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::
          RpcMethodHandler<enclave::Service, ::rpc::Request, ::rpc::Response>(
              [](enclave::Service* service,
                 ::grpc_impl::ServerContext* ctx,
                 const ::rpc::Request* req,
                 ::rpc::Response* resp) {
                return service->process(ctx, req, resp);
              },
              this)));
}

enclave::Service::~Service() {}

::grpc::Status enclave::Service::attest(::grpc::ServerContext* context,
                                        const ::rpc::Empty* request,
                                        ::rpc::Attestation* response)
{
  (void)context;
  (void)request;
  (void)response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status enclave::Service::status(::grpc::ServerContext* context,
                                        const ::rpc::Empty* request,
                                        ::rpc::Status* response)
{
  (void)context;
  (void)request;
  (void)response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status enclave::Service::process(::grpc::ServerContext* context,
                                         const ::rpc::Request* request,
                                         ::rpc::Response* response)
{
  (void)context;
  (void)request;
  (void)response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

}  // namespace rpc
