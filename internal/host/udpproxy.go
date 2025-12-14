package host

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	internalv1 "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// handleUDPProxy handles UDP packets wrapped in HTTP/2 from tunn connect clients
func (p *ProxyServer) handleUDPProxy(w http.ResponseWriter, r *http.Request) {
	// Extract tunnel ID from path: /udp/{tunnel_id}
	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(pathParts) != 2 || pathParts[0] != "udp" {
		http.Error(w, "invalid UDP endpoint path", http.StatusNotFound)
		return
	}
	tunnelID := pathParts[1]

	// Only accept POST requests
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read UDP packet from request body
	packetData, err := io.ReadAll(r.Body)
	if err != nil {
		common.LogError("failed to read UDP packet", "error", err)
		http.Error(w, "failed to read packet", http.StatusBadRequest)
		return
	}

	// Get source address from header (set by tunn connect)
	sourceAddr := r.Header.Get("X-UDP-Source")
	if sourceAddr == "" {
		http.Error(w, "missing X-UDP-Source header", http.StatusBadRequest)
		return
	}

	common.LogDebug("UDP packet received",
		"tunnel_id", tunnelID,
		"source", sourceAddr,
		"bytes", len(packetData))

	// Find the tunnel connection - try local first
	p.tunnelServer.mu.RLock()
	conn, exists := p.tunnelServer.tunnels[tunnelID]
	p.tunnelServer.mu.RUnlock()

	// If not found locally, check cache and probe other nodes
	if !exists {
		common.LogInfo("tunnel not found locally, probing other nodes", "tunnel_id", tunnelID)

		// Check cache first
		p.cacheMu.RLock()
		nodeAddr, cached := p.tunnelCache[tunnelID]
		p.cacheMu.RUnlock()

		if cached {
			common.LogInfo("found tunnel in cache, forwarding to node", "tunnel_id", tunnelID, "node", nodeAddr)
			p.forwardUdpToNode(w, r, tunnelID, sourceAddr, packetData, nodeAddr)
			return
		}

		// Probe other nodes
		for addr, client := range p.nodeClients {
			common.LogInfo("probing node for tunnel", "tunnel_id", tunnelID, "node", addr)
			resp, err := client.FindTunnel(context.Background(), &internalv1.FindTunnelRequest{TunnelId: tunnelID})
			if err != nil {
				common.LogError("failed to probe node", "error", err, "node", addr)
				continue
			}

			if resp.Found {
				common.LogInfo("tunnel found on node", "tunnel_id", tunnelID, "node", resp.NodeAddress)

				// Update cache
				p.cacheMu.Lock()
				p.tunnelCache[tunnelID] = resp.NodeAddress
				p.cacheMu.Unlock()

				// Forward packet to that node
				p.forwardUdpToNode(w, r, tunnelID, sourceAddr, packetData, resp.NodeAddress)
				return
			}
		}

		// Not found on any node
		common.LogError("tunnel not found on any node", "tunnel_id", tunnelID)
		http.Error(w, "tunnel not found", http.StatusNotFound)
		return
	}

	// Create a response channel for this packet
	// UDP is request-response at the application level for many protocols
	respChan := make(chan []byte, 1)
	connID := fmt.Sprintf("udp-%s-%d", sourceAddr, time.Now().UnixNano())

	// Register response handler
	conn.mu.Lock()
	if conn.udpResponses == nil {
		conn.udpResponses = make(map[string]chan []byte)
	}
	conn.udpResponses[connID] = respChan
	conn.mu.Unlock()

	// Clean up response channel when done
	defer func() {
		conn.mu.Lock()
		delete(conn.udpResponses, connID)
		conn.mu.Unlock()
		close(respChan)
	}()

	// Send UDP packet to the tunnel
	udpPacket := &pb.UdpPacket{
		TunnelId:           tunnelID,
		SourceAddress:      sourceAddr,
		DestinationAddress: "", // Will be filled in by serve client from RegisterClient.udp_target_address
		Data:               packetData,
		FromClient:         false, // From proxy to client
		TimestampMs:        time.Now().UnixMilli(),
	}

	err = conn.Stream.Send(&pb.TunnelMessage{
		Message: &pb.TunnelMessage_UdpPacket{
			UdpPacket: udpPacket,
		},
	})
	if err != nil {
		common.LogError("failed to send UDP packet to tunnel",
			"tunnel_id", tunnelID,
			"error", err)
		http.Error(w, "failed to forward packet", http.StatusInternalServerError)
		return
	}

	// Wait for response (with timeout)
	// Many UDP protocols are request-response (DNS, game protocols, etc.)
	select {
	case responseData := <-respChan:
		// Send response back to tunn connect client
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		w.Write(responseData)
		common.LogDebug("UDP response sent",
			"tunnel_id", tunnelID,
			"bytes", len(responseData))
	case <-time.After(5 * time.Second):
		// Timeout - no response from server
		// This is OK for UDP, just return empty response
		w.WriteHeader(http.StatusNoContent)
		common.LogDebug("UDP request timeout (no response)",
			"tunnel_id", tunnelID)
	case <-r.Context().Done():
		// Client disconnected
		http.Error(w, "request cancelled", http.StatusRequestTimeout)
	}
}

// forwardUdpToNode forwards a UDP packet to another node in the cluster
func (p *ProxyServer) forwardUdpToNode(w http.ResponseWriter, r *http.Request, tunnelID, sourceAddr string, packetData []byte, nodeAddr string) {
	// Get the internal gRPC client for this node
	client, exists := p.nodeClients[nodeAddr]
	if !exists {
		common.LogError("no gRPC client for node", "node", nodeAddr)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Forward the UDP packet via gRPC
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := client.ForwardUdpPacket(ctx, &internalv1.ForwardUdpPacketRequest{
		TunnelId:      tunnelID,
		SourceAddress: sourceAddr,
		Data:          packetData,
	})

	if err != nil {
		common.LogError("failed to forward UDP packet to node", "error", err, "node", nodeAddr)
		http.Error(w, "failed to forward packet", http.StatusInternalServerError)
		return
	}

	if !resp.Success {
		common.LogError("node failed to forward UDP packet", "error", resp.ErrorMessage, "node", nodeAddr)
		http.Error(w, "failed to forward packet", http.StatusInternalServerError)
		return
	}

	// Send response back to tunn connect client
	if len(resp.ResponseData) > 0 {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		w.Write(resp.ResponseData)
		common.LogDebug("UDP response forwarded from remote node",
			"tunnel_id", tunnelID,
			"node", nodeAddr,
			"bytes", len(resp.ResponseData))
	} else {
		// No response - return 204 No Content
		w.WriteHeader(http.StatusNoContent)
		common.LogDebug("UDP request timeout on remote node (no response)",
			"tunnel_id", tunnelID,
			"node", nodeAddr)
	}
}
