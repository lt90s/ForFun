do
    local private_pcep = Proto("HW_PCEP", "Huawei Private PCEP")
	local message_type = {
		[1] = "PCEP OPEN (1)", [2] = "PCEP KeepAlive (2)", [3] = "PCEP PCReq (3)", [4] = "PCEP PCRep (4)",
		[5] = "PCEP Notification (5)", [6] = "PCEP Error (6)", [7] = "PCEP Close (7)",
		[10] = "PCEP PCRpt (10)", [11] = "PCEP PCUpd (11)"
	}
    local f_ver_flag = ProtoField.uint8("HW_PCEP.ver_flag", "PCEP Version", base.HEX)
    local f_msg_type = ProtoField.uint8("HW_PCEP.msg_type", "Message Type", base.DEC)
	local f_msg_len = ProtoField.uint16("Hw_PCEP.msg_len", "Message Length", base.DEC)
	
	

    private_pcep.fields = { f_ver_flag, f_msg_type, f_msg_len }

    local data_dis = Dissector.get("data")
	local function get_bits(v, s, e)
		local bits = {0, 0, 0 , 0, 0, 0, 0, 0}
		for i = 1, 8 do
			if v < 1 then
				break
			end
			if v % 2 == 0 then
				bits[i] = 0
			else
				bits[i] = 1
			end
			v = math.floor(v / 2)
		end
		local r = ''
		local num = 0
		local idx = e + 1
		while idx <= 8 do
			r = r .. '.'
			idx = idx + 1
		end
		idx = e
		while idx >= s do
			r = r .. bits[idx]
			num = num * 2 + bits[idx]
			idx = idx - 1
		end
		idx = s - 1
		while idx > 0 do
			r = r .. '.'
			idx = idx - 1
		end
		return string.sub(r, 1, 4) .. ' ' .. string.sub(r, 5, 8) .. '  ' .. num
	end
    local function private_pcep_dissector(buf, pkt, root)
	 	local buf_len = buf:len()
		local bytes = buf:range(0):bytes()
		if buf_len < 4 then
			return false
		end
    	local msg_type = buf(1, 1)
		
		pkt.cols.protocol = "HW_PCEP"

		if message_type[msg_type:uint()] == nil then
			pkt.cols.info = "trailing data"
			local t = root:add(private_pcep, buf)
			t:add(buf(0, buf_len), "data")
			return true
		end
		pkt.cols.info = message_type[msg_type:uint()]
		local ver_flag = buf(0, 1)
    	local msg_len = buf(2, 2)
    	local t = root:add(private_pcep, buf)

		-- message common header
		local d = t:add(buf(0, 4), "PCEP Common Header " .. message_type[msg_type:uint()])
		d:add(buf(0, 1), "PCEP Version: " .. get_bits(ver_flag:uint(), 6, 8))
		d:add(buf(0, 1), "Flags: " .. get_bits(ver_flag:uint(), 1, 5))
    	d:add(f_msg_type, msg_type)
    	d:add(f_msg_len, msg_len)
		--
		if buf_len < 8 then
			return true
		end
		
		local offset = 4
		while offset + 4 <= buf_len do
			obj_class = buf(offset, 1)
			obj_length = buf(offset + 2, 2)
			d = t:add(buf(offset, 4), "PCEP OBJECT")
			d:add(buf(offset, 1), "Object Class: " .. obj_class:uint())
			d:add(buf(offset + 1, 1), "Object Type: " .. get_bits(buf(offset + 1,1):uint(), 5, 8))
			d:add(buf(offset + 1, 1), "Res Flags: " .. get_bits(buf(offset + 1, 1):uint(), 3, 4))
			d:add(buf(offset + 1, 1), "P Flagg: " .. get_bits(buf(offset + 1, 1):uint(), 2, 2))
			d:add(buf(offset + 1, 1), "I Flagg: " .. get_bits(buf(offset + 1, 1):uint(), 1, 1))
			d:add(buf(offset + 2, 2), "Object Length: " .. obj_length:uint())
			offset = offset + obj_length:uint()
		end
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
