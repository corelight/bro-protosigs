module ProtoSig;

export {
	redef record connection += {
		## The protocol detected purely by signature matching.
		protosig: string &optional &log;
	};

	redef record Conn::Info += {
		## The protocol detected purely by signature matching.
		protosig: string &optional &log;
	};
}

function ProtoSig::match(state: signature_state, data: string): bool
	{
	local proto = gsub(state$sig_id, /^protosig_/, "");
	state$conn$protosig = proto;
	
	# We just always return false because we're done.  We don't
	# actually want the signature match to happen.
	return F;
	}


event connection_state_remove(c: connection) &priority=3
	{
	if ( c?$protosig )
		c$conn$protosig = c$protosig;
	}
