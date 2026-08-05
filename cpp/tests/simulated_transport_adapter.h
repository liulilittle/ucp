#pragma once

/**
 * MIT License
 *
 * Copyright (c) 2026 PPP PRIVATE NETWORK(TM) X
 *
 * Test-only adapter: bridges NetworkSimulator::SimulatedTransport onto the
 * transport::IBindableTransport contract so a real UcpServer/UcpConnection
 * protocol stack can run over the simulated network (loss, delay, jitter,
 * duplication, reordering, bandwidth shaping).
 *
 * Without this adapter the integration tests sent raw datagrams directly into
 * the simulator, bypassing the UCP protocol stack (handshake, ACK, retransmit,
 * congestion control) entirely. This adapter makes the protocol stack the
 * actual sender/receiver, so the measured metrics come from real UCP behavior.
 */

#include "ucp/transport/ibindable_transport.h"
#include "ucp/ucp_vector.h"
#include "ucp/ucp_types.h"

#include <memory>

#include "network_simulator.h"

namespace ucp_test {

/** @brief Adapts a NetworkSimulator::SimulatedTransport to IBindableTransport.
 *
 *  Endpoint addresses are ignored (the simulator routes purely by port).
 *  Inbound simulated datagrams are forwarded to ITransport subscribers via
 *  RaiseOnDatagram; outbound Send() calls are routed into the simulator with
 *  the destination port taken from the Endpoint. */
class SimulatedTransportAdapter : public ucp::transport::IBindableTransport {
  public:
    SimulatedTransportAdapter(NetworkSimulator* sim, const ucp::string& name) noexcept
        : sim_(sim), inner_(sim ? sim->CreateTransport(name) : NULLPTR), ownsInner_(true), name_(name) {}

    explicit SimulatedTransportAdapter(NetworkSimulator::SimulatedTransport* inner) noexcept
        : sim_(inner ? inner->simulator : NULLPTR), inner_(inner), ownsInner_(false), name_("inner") {}

    SimulatedTransportAdapter(const SimulatedTransportAdapter&) = delete;
    SimulatedTransportAdapter& operator=(const SimulatedTransportAdapter&) = delete;
    SimulatedTransportAdapter(SimulatedTransportAdapter&&) = delete;
    SimulatedTransportAdapter& operator=(SimulatedTransportAdapter&&) = delete;

    ~SimulatedTransportAdapter() noexcept override {
        Stop();
        if (ownsInner_ && inner_ != NULLPTR) {
            inner_->Dispose();
        }
    }

    void Start(int port) noexcept override {
        if (inner_ == NULLPTR) {
            return;
        }
        inner_->Start(port);
        inner_->on_datagram = [this](const uint8_t* data, int length, int sourcePort) noexcept -> void {
            if (length <= 0) {
                return;
            }
            adapterRecvCount++;
            ucp::Endpoint src;
            src.address = "127.0.0.1";
            src.port = (uint16_t)sourcePort;
            ucp::vector<uint8_t> datagram(data, data + length);
            RaiseOnDatagram(datagram, src);
        };
    }

    void Stop() noexcept override {
        if (inner_ == NULLPTR) {
            return;
        }
        inner_->on_datagram = nullptr;
        inner_->Stop();
    }

    ucp::Endpoint LocalEndpoint() noexcept override {
        ucp::Endpoint ep;
        if (inner_ == NULLPTR) {
            return ep;
        }
        ep.address = "127.0.0.1";
        ep.port = (uint16_t)inner_->local_port;
        return ep;
    }

    void Send(const ucp::vector<uint8_t>& data, const ucp::Endpoint& remote) noexcept override {
        if (inner_ == NULLPTR) {
            return;
        }
        adapterSendCount++;
        inner_->Send(data.data(), static_cast<int>(data.size()), remote.port);
    }

    std::atomic<int64_t> adapterSendCount{0};
    std::atomic<int64_t> adapterRecvCount{0};

    NetworkSimulator::SimulatedTransport* Inner() noexcept { return inner_; }

    const NetworkSimulator::SimulatedTransport* Inner() const noexcept { return inner_; }

  private:
    NetworkSimulator* sim_;
    NetworkSimulator::SimulatedTransport* inner_;
    bool ownsInner_;
    ucp::string name_;
};

} // namespace ucp_test
