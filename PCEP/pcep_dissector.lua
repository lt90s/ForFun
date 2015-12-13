do
    local private_pcep = Proto("HW_PCEP", "Huawei Private PCEP")
    local f_ver_flag = ProtoField.uint8("HW_PCEP.ver_flag", "ver_flag", base.HEX)
    local f_msg_type = ProtoField.uint8("HW_PCEP.msg_type", "msg_type", base.DEC,
    						{[1] = "PCEP OPEN", [2] = "PCEP KeepAlive", [3] = "PCEP PCReq", [4] = "PCEP PCRep",
							[5] = "PCEP Notification", [6] = "PCEP Error", [7] = "PCEP Close",
							[10] = "PCEP PCupt", [11] = "PCEP PCunknon"})
	local f_msg_len = ProtoField.uint16("Hw_PCEP.msg_len", "msg_len")

    private_pcep.fields = { f_ver_flag, f_msg_type, f_msg_len }

    local data_dis = Dissector.get("data")

    local function private_pcep_dissector(buf, pkt, root)
    	print "hello world"
	 	local buf_len = buf:len()
		local flag_ver = buf(0, 1)
--[[
		if (flag_ver ~= 0x20) then
    	    return false
    	end
--]]
    	local msg_type = buf(1, 1)
    	local msg_len = buf(2, 2)
    	local t = root:add(private_pcep, buf)
    	pkt.cols.protocol = "whatever"
    	t:add(f_ver_flag, flag_ver)
    	t:add(f_msg_type, msg_type)
    	t:add(f_msg_len, msg_len)
    	return true
    end

    function private_pcep.dissector(buf, pkt, root)
        if private_pcep_dissector(buf, pkt, root) then
                -- ok
        else
            data_dis:call(buf, pkt, root)
        end
    end
    local tcp_pcep_table = DissectorTable.get("tcp.port")
    tcp_pcep_table:add(4189, private_pcep)
end
