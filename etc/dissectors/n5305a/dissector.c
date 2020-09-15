#include "dissector.h"

int disectN5305A(tvbuff_t *const buffer, packet_info *const pinfo, proto_tree *const tree, void *const data)
{
	const guint len = tvb_captured_length(buffer);
	(void)data;

	if (!len || len != tvb_reported_length(buffer))
		return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "N5305A Protocol Analyzer");
	proto_tree *subtree = proto_tree_add_subtree(tree, buffer, 0, -1, ettN5305A, NULL, "N5305A Protocol Analyzer");
	proto_tree_add_item(subtree, packetDirection, pinfo->srcport == 1029 ? dirHost : dirAnalyzer, 0, -1, ENC_ASCII);

	return len;
}
