setwd("/home/jasmine/R_pcap")
dyn.load("pcap_parser.so")

read_pcap_file <- function (fname, debug) {
       .Call ("read_pcap_file", fname, debug)
       return (0)
}

get_tcp_flow_table <- function () {
	init_ips   <- .Call("get_tcp_init_ipaddr_vector")
	resp_ips   <- .Call("get_tcp_resp_ipaddr_vector")
	init_ports <- .Call("get_tcp_init_port_vector")
	resp_ports <- .Call("get_tcp_resp_port_vector")
	start_time <- .Call("get_tcp_start_time_vector")
	flow_id    <- .Call("get_flow_id_vector")

	flow_table <- data.frame (InitiatorIP = init_ips, ResponderIP = resp_ips, InitiatorPort = init_ports, ResponderPort = resp_ports, 
                                    StartTime = start_time, FlowId = flow_id)
	return(flow_table)
}

get_tcp_flow_info <- function (flow_id) {
	init_timestamps <- .Call("get_tcp_flow_init_timestamps_vector", flow_id)
	init_seq_nums   <- .Call("get_tcp_flow_init_seq_nums_vector", flow_id)
	init_ack_nums   <- .Call("get_tcp_flow_init_ack_nums_vector", flow_id)
	init_window_sz  <- .Call("get_tcp_flow_init_window_size_vector", flow_id)

	resp_timestamps <- .Call("get_tcp_flow_resp_timestamps_vector", flow_id)
	resp_ack_nums   <- .Call("get_tcp_flow_resp_ack_nums_vector", flow_id)
	resp_seq_nums   <- .Call("get_tcp_flow_resp_seq_nums_vector", flow_id)
	resp_window_sz  <- .Call("get_tcp_flow_resp_window_size_vector", flow_id)

	flow <- list()
	flow$initiator  <- data.frame (TimeStamp = init_timestamps, SeqNums = init_seq_nums, AckNums = init_ack_nums, WindowSz = init_window_sz)
	flow$responder  <- data.frame (TimeStamp = resp_timestamps, SeqNums = resp_seq_nums, AckNums = resp_ack_nums, WindowSz = resp_window_sz)
	
	return (flow)
}	

plot_tcp_flow_initiator_seq <- function (flow) {
	info <- flow$initiator
	plot(info$TimeStamp, info$SeqNums)
}

plot_tcp_flow_responder_seq <- function (flow_info) {
	info <- flow$responder
	plot(info$TimeStamp, info$SeqNums)
}

plot_tcp_flow_initiator_win <- function (flow) {
	info <- flow$initiator
	plot(info$TimeStamp, info$WindowSz)
}

plot_tcp_flow_responder_win <- function (flow) {
	info <- flow$responder
	plot(info$TimeStamp, info$WindowSz)
}
