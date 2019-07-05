# Check 64bit AVX/AVX2 instructions w/ source swapping

	.text
_start:
# Tests for op ymm/mem256, ymm, ymm
	vaddpd %ymm14,%ymm6,%ymm2
	vaddps %ymm14,%ymm6,%ymm2
	vaddsubpd %ymm14,%ymm6,%ymm2
	vaddsubps %ymm14,%ymm6,%ymm2
	vandnpd %ymm14,%ymm6,%ymm2
	vandnps %ymm14,%ymm6,%ymm2
	vandpd %ymm14,%ymm6,%ymm2
	vandps %ymm14,%ymm6,%ymm2
	vdivpd %ymm14,%ymm6,%ymm2
	vdivps %ymm14,%ymm6,%ymm2
	vhaddpd %ymm14,%ymm6,%ymm2
	vhaddps %ymm14,%ymm6,%ymm2
	vhsubpd %ymm14,%ymm6,%ymm2
	vhsubps %ymm14,%ymm6,%ymm2
	vmaxpd %ymm14,%ymm6,%ymm2
	vmaxps %ymm14,%ymm6,%ymm2
	vminpd %ymm14,%ymm6,%ymm2
	vminps %ymm14,%ymm6,%ymm2
	vmulpd %ymm14,%ymm6,%ymm2
	vmulps %ymm14,%ymm6,%ymm2
	vorpd %ymm14,%ymm6,%ymm2
	vorps %ymm14,%ymm6,%ymm2
	vpaddb %ymm14,%ymm6,%ymm2
	vpaddw %ymm14,%ymm6,%ymm2
	vpaddd %ymm14,%ymm6,%ymm2
	vpaddq %ymm14,%ymm6,%ymm2
	vpaddsb %ymm14,%ymm6,%ymm2
	vpaddsw %ymm14,%ymm6,%ymm2
	vpaddusb %ymm14,%ymm6,%ymm2
	vpaddusw %ymm14,%ymm6,%ymm2
	vpand %ymm14,%ymm6,%ymm2
	vpandn %ymm14,%ymm6,%ymm2
	vpavgb %ymm14,%ymm6,%ymm2
	vpavgw %ymm14,%ymm6,%ymm2
	vpcmpeqb %ymm14,%ymm6,%ymm2
	vpcmpeqw %ymm14,%ymm6,%ymm2
	vpcmpeqd %ymm14,%ymm6,%ymm2
	vpcmpeqq %ymm14,%ymm6,%ymm2
	vpcmpgtb %ymm14,%ymm6,%ymm2
	vpcmpgtw %ymm14,%ymm6,%ymm2
	vpcmpgtd %ymm14,%ymm6,%ymm2
	vpcmpgtq %ymm14,%ymm6,%ymm2
	vpmaddwd %ymm14,%ymm6,%ymm2
	vpmaxsb %ymm14,%ymm6,%ymm2
	vpmaxsw %ymm14,%ymm6,%ymm2
	vpmaxsd %ymm14,%ymm6,%ymm2
	vpmaxub %ymm14,%ymm6,%ymm2
	vpmaxuw %ymm14,%ymm6,%ymm2
	vpmaxud %ymm14,%ymm6,%ymm2
	vpminsb %ymm14,%ymm6,%ymm2
	vpminsw %ymm14,%ymm6,%ymm2
	vpminsd %ymm14,%ymm6,%ymm2
	vpminub %ymm14,%ymm6,%ymm2
	vpminuw %ymm14,%ymm6,%ymm2
	vpminud %ymm14,%ymm6,%ymm2
	vpmulhuw %ymm14,%ymm6,%ymm2
	vpmulhw %ymm14,%ymm6,%ymm2
	vpmullw %ymm14,%ymm6,%ymm2
	vpmulld %ymm14,%ymm6,%ymm2
	vpmuludq %ymm14,%ymm6,%ymm2
	vpmuldq %ymm14,%ymm6,%ymm2
	vpor %ymm14,%ymm6,%ymm2
	vpsadbw %ymm14,%ymm6,%ymm2
	vpsubb %ymm14,%ymm6,%ymm2
	vpsubw %ymm14,%ymm6,%ymm2
	vpsubd %ymm14,%ymm6,%ymm2
	vpsubq %ymm14,%ymm6,%ymm2
	vpsubsb %ymm14,%ymm6,%ymm2
	vpsubsw %ymm14,%ymm6,%ymm2
	vpsubusb %ymm14,%ymm6,%ymm2
	vpsubusw %ymm14,%ymm6,%ymm2
	vpxor %ymm14,%ymm6,%ymm2
	vsubpd %ymm14,%ymm6,%ymm2
	vsubps %ymm14,%ymm6,%ymm2
	vxorpd %ymm14,%ymm6,%ymm2
	vxorps %ymm14,%ymm6,%ymm2
	vcmpeqpd %ymm14,%ymm6,%ymm2
	vcmpltpd %ymm14,%ymm6,%ymm2
	vcmplepd %ymm14,%ymm6,%ymm2
	vcmpunordpd %ymm14,%ymm6,%ymm2
	vcmpneqpd %ymm14,%ymm6,%ymm2
	vcmpnltpd %ymm14,%ymm6,%ymm2
	vcmpnlepd %ymm14,%ymm6,%ymm2
	vcmpordpd %ymm14,%ymm6,%ymm2
	vcmpeq_uqpd %ymm14,%ymm6,%ymm2
	vcmpngepd %ymm14,%ymm6,%ymm2
	vcmpngtpd %ymm14,%ymm6,%ymm2
	vcmpfalsepd %ymm14,%ymm6,%ymm2
	vcmpneq_oqpd %ymm14,%ymm6,%ymm2
	vcmpgepd %ymm14,%ymm6,%ymm2
	vcmpgtpd %ymm14,%ymm6,%ymm2
	vcmptruepd %ymm14,%ymm6,%ymm2
	vcmpeq_ospd %ymm14,%ymm6,%ymm2
	vcmplt_oqpd %ymm14,%ymm6,%ymm2
	vcmple_oqpd %ymm14,%ymm6,%ymm2
	vcmpunord_spd %ymm14,%ymm6,%ymm2
	vcmpneq_uspd %ymm14,%ymm6,%ymm2
	vcmpnlt_uqpd %ymm14,%ymm6,%ymm2
	vcmpnle_uqpd %ymm14,%ymm6,%ymm2
	vcmpord_spd %ymm14,%ymm6,%ymm2
	vcmpeq_uspd %ymm14,%ymm6,%ymm2
	vcmpnge_uqpd %ymm14,%ymm6,%ymm2
	vcmpngt_uqpd %ymm14,%ymm6,%ymm2
	vcmpfalse_ospd %ymm14,%ymm6,%ymm2
	vcmpneq_ospd %ymm14,%ymm6,%ymm2
	vcmpge_oqpd %ymm14,%ymm6,%ymm2
	vcmpgt_oqpd %ymm14,%ymm6,%ymm2
	vcmptrue_uspd %ymm14,%ymm6,%ymm2
	vcmpeqps %ymm14,%ymm6,%ymm2
	vcmpltps %ymm14,%ymm6,%ymm2
	vcmpleps %ymm14,%ymm6,%ymm2
	vcmpunordps %ymm14,%ymm6,%ymm2
	vcmpneqps %ymm14,%ymm6,%ymm2
	vcmpnltps %ymm14,%ymm6,%ymm2
	vcmpnleps %ymm14,%ymm6,%ymm2
	vcmpordps %ymm14,%ymm6,%ymm2
	vcmpeq_uqps %ymm14,%ymm6,%ymm2
	vcmpngeps %ymm14,%ymm6,%ymm2
	vcmpngtps %ymm14,%ymm6,%ymm2
	vcmpfalseps %ymm14,%ymm6,%ymm2
	vcmpneq_oqps %ymm14,%ymm6,%ymm2
	vcmpgeps %ymm14,%ymm6,%ymm2
	vcmpgtps %ymm14,%ymm6,%ymm2
	vcmptrueps %ymm14,%ymm6,%ymm2
	vcmpeq_osps %ymm14,%ymm6,%ymm2
	vcmplt_oqps %ymm14,%ymm6,%ymm2
	vcmple_oqps %ymm14,%ymm6,%ymm2
	vcmpunord_sps %ymm14,%ymm6,%ymm2
	vcmpneq_usps %ymm14,%ymm6,%ymm2
	vcmpnlt_uqps %ymm14,%ymm6,%ymm2
	vcmpnle_uqps %ymm14,%ymm6,%ymm2
	vcmpord_sps %ymm14,%ymm6,%ymm2
	vcmpeq_usps %ymm14,%ymm6,%ymm2
	vcmpnge_uqps %ymm14,%ymm6,%ymm2
	vcmpngt_uqps %ymm14,%ymm6,%ymm2
	vcmpfalse_osps %ymm14,%ymm6,%ymm2
	vcmpneq_osps %ymm14,%ymm6,%ymm2
	vcmpge_oqps %ymm14,%ymm6,%ymm2
	vcmpgt_oqps %ymm14,%ymm6,%ymm2
	vcmptrue_usps %ymm14,%ymm6,%ymm2

# Tests for op imm8, ymm/mem256, ymm, ymm
	vcmppd $7,%ymm14,%ymm6,%ymm2
	vcmpps $7,%ymm14,%ymm6,%ymm2

# Tests for op xmm/mem128, xmm, xmm
	vaddpd %xmm14,%xmm6,%xmm2
	vaddps %xmm14,%xmm6,%xmm2
	vaddsubpd %xmm14,%xmm6,%xmm2
	vaddsubps %xmm14,%xmm6,%xmm2
	vandnpd %xmm14,%xmm6,%xmm2
	vandnps %xmm14,%xmm6,%xmm2
	vandpd %xmm14,%xmm6,%xmm2
	vandps %xmm14,%xmm6,%xmm2
	vdivpd %xmm14,%xmm6,%xmm2
	vdivps %xmm14,%xmm6,%xmm2
	vhaddpd %xmm14,%xmm6,%xmm2
	vhaddps %xmm14,%xmm6,%xmm2
	vhsubpd %xmm14,%xmm6,%xmm2
	vhsubps %xmm14,%xmm6,%xmm2
	vmaxpd %xmm14,%xmm6,%xmm2
	vmaxps %xmm14,%xmm6,%xmm2
	vminpd %xmm14,%xmm6,%xmm2
	vminps %xmm14,%xmm6,%xmm2
	vmulpd %xmm14,%xmm6,%xmm2
	vmulps %xmm14,%xmm6,%xmm2
	vorpd %xmm14,%xmm6,%xmm2
	vorps %xmm14,%xmm6,%xmm2
	vpaddb %xmm14,%xmm6,%xmm2
	vpaddw %xmm14,%xmm6,%xmm2
	vpaddd %xmm14,%xmm6,%xmm2
	vpaddq %xmm14,%xmm6,%xmm2
	vpaddsb %xmm14,%xmm6,%xmm2
	vpaddsw %xmm14,%xmm6,%xmm2
	vpaddusb %xmm14,%xmm6,%xmm2
	vpaddusw %xmm14,%xmm6,%xmm2
	vpand %xmm14,%xmm6,%xmm2
	vpandn %xmm14,%xmm6,%xmm2
	vpavgb %xmm14,%xmm6,%xmm2
	vpavgw %xmm14,%xmm6,%xmm2
	vpcmpeqb %xmm14,%xmm6,%xmm2
	vpcmpeqw %xmm14,%xmm6,%xmm2
	vpcmpeqd %xmm14,%xmm6,%xmm2
	vpcmpeqq %xmm14,%xmm6,%xmm2
	vpcmpgtb %xmm14,%xmm6,%xmm2
	vpcmpgtw %xmm14,%xmm6,%xmm2
	vpcmpgtd %xmm14,%xmm6,%xmm2
	vpcmpgtq %xmm14,%xmm6,%xmm2
	vpmaddwd %xmm14,%xmm6,%xmm2
	vpmaxsb %xmm14,%xmm6,%xmm2
	vpmaxsw %xmm14,%xmm6,%xmm2
	vpmaxsd %xmm14,%xmm6,%xmm2
	vpmaxub %xmm14,%xmm6,%xmm2
	vpmaxuw %xmm14,%xmm6,%xmm2
	vpmaxud %xmm14,%xmm6,%xmm2
	vpminsb %xmm14,%xmm6,%xmm2
	vpminsw %xmm14,%xmm6,%xmm2
	vpminsd %xmm14,%xmm6,%xmm2
	vpminub %xmm14,%xmm6,%xmm2
	vpminuw %xmm14,%xmm6,%xmm2
	vpminud %xmm14,%xmm6,%xmm2
	vpmulhuw %xmm14,%xmm6,%xmm2
	vpmulhw %xmm14,%xmm6,%xmm2
	vpmullw %xmm14,%xmm6,%xmm2
	vpmulld %xmm14,%xmm6,%xmm2
	vpmuludq %xmm14,%xmm6,%xmm2
	vpmuldq %xmm14,%xmm6,%xmm2
	vpor %xmm14,%xmm6,%xmm2
	vpsadbw %xmm14,%xmm6,%xmm2
	vpsubb %xmm14,%xmm6,%xmm2
	vpsubw %xmm14,%xmm6,%xmm2
	vpsubd %xmm14,%xmm6,%xmm2
	vpsubq %xmm14,%xmm6,%xmm2
	vpsubsb %xmm14,%xmm6,%xmm2
	vpsubsw %xmm14,%xmm6,%xmm2
	vpsubusb %xmm14,%xmm6,%xmm2
	vpsubusw %xmm14,%xmm6,%xmm2
	vpxor %xmm14,%xmm6,%xmm2
	vsubpd %xmm14,%xmm6,%xmm2
	vsubps %xmm14,%xmm6,%xmm2
	vxorpd %xmm14,%xmm6,%xmm2
	vxorps %xmm14,%xmm6,%xmm2
	vcmpeqpd %xmm14,%xmm6,%xmm2
	vcmpltpd %xmm14,%xmm6,%xmm2
	vcmplepd %xmm14,%xmm6,%xmm2
	vcmpunordpd %xmm14,%xmm6,%xmm2
	vcmpneqpd %xmm14,%xmm6,%xmm2
	vcmpnltpd %xmm14,%xmm6,%xmm2
	vcmpnlepd %xmm14,%xmm6,%xmm2
	vcmpordpd %xmm14,%xmm6,%xmm2
	vcmpeq_uqpd %xmm14,%xmm6,%xmm2
	vcmpngepd %xmm14,%xmm6,%xmm2
	vcmpngtpd %xmm14,%xmm6,%xmm2
	vcmpfalsepd %xmm14,%xmm6,%xmm2
	vcmpneq_oqpd %xmm14,%xmm6,%xmm2
	vcmpgepd %xmm14,%xmm6,%xmm2
	vcmpgtpd %xmm14,%xmm6,%xmm2
	vcmptruepd %xmm14,%xmm6,%xmm2
	vcmpeq_ospd %xmm14,%xmm6,%xmm2
	vcmplt_oqpd %xmm14,%xmm6,%xmm2
	vcmple_oqpd %xmm14,%xmm6,%xmm2
	vcmpunord_spd %xmm14,%xmm6,%xmm2
	vcmpneq_uspd %xmm14,%xmm6,%xmm2
	vcmpnlt_uqpd %xmm14,%xmm6,%xmm2
	vcmpnle_uqpd %xmm14,%xmm6,%xmm2
	vcmpord_spd %xmm14,%xmm6,%xmm2
	vcmpeq_uspd %xmm14,%xmm6,%xmm2
	vcmpnge_uqpd %xmm14,%xmm6,%xmm2
	vcmpngt_uqpd %xmm14,%xmm6,%xmm2
	vcmpfalse_ospd %xmm14,%xmm6,%xmm2
	vcmpneq_ospd %xmm14,%xmm6,%xmm2
	vcmpge_oqpd %xmm14,%xmm6,%xmm2
	vcmpgt_oqpd %xmm14,%xmm6,%xmm2
	vcmptrue_uspd %xmm14,%xmm6,%xmm2
	vcmpeqps %xmm14,%xmm6,%xmm2
	vcmpltps %xmm14,%xmm6,%xmm2
	vcmpleps %xmm14,%xmm6,%xmm2
	vcmpunordps %xmm14,%xmm6,%xmm2
	vcmpneqps %xmm14,%xmm6,%xmm2
	vcmpnltps %xmm14,%xmm6,%xmm2
	vcmpnleps %xmm14,%xmm6,%xmm2
	vcmpordps %xmm14,%xmm6,%xmm2
	vcmpeq_uqps %xmm14,%xmm6,%xmm2
	vcmpngeps %xmm14,%xmm6,%xmm2
	vcmpngtps %xmm14,%xmm6,%xmm2
	vcmpfalseps %xmm14,%xmm6,%xmm2
	vcmpneq_oqps %xmm14,%xmm6,%xmm2
	vcmpgeps %xmm14,%xmm6,%xmm2
	vcmpgtps %xmm14,%xmm6,%xmm2
	vcmptrueps %xmm14,%xmm6,%xmm2
	vcmpeq_osps %xmm14,%xmm6,%xmm2
	vcmplt_oqps %xmm14,%xmm6,%xmm2
	vcmple_oqps %xmm14,%xmm6,%xmm2
	vcmpunord_sps %xmm14,%xmm6,%xmm2
	vcmpneq_usps %xmm14,%xmm6,%xmm2
	vcmpnlt_uqps %xmm14,%xmm6,%xmm2
	vcmpnle_uqps %xmm14,%xmm6,%xmm2
	vcmpord_sps %xmm14,%xmm6,%xmm2
	vcmpeq_usps %xmm14,%xmm6,%xmm2
	vcmpnge_uqps %xmm14,%xmm6,%xmm2
	vcmpngt_uqps %xmm14,%xmm6,%xmm2
	vcmpfalse_osps %xmm14,%xmm6,%xmm2
	vcmpneq_osps %xmm14,%xmm6,%xmm2
	vcmpge_oqps %xmm14,%xmm6,%xmm2
	vcmpgt_oqps %xmm14,%xmm6,%xmm2
	vcmptrue_usps %xmm14,%xmm6,%xmm2

# Tests for op imm8, xmm/mem128, xmm, xmm
	vcmppd $7,%xmm14,%xmm6,%xmm2
	vcmpps $7,%xmm14,%xmm6,%xmm2

# Tests for op xmm/mem64, xmm
	vcomisd %xmm14,%xmm6
	vucomisd %xmm14,%xmm6

# Tests for op imm8, xmm/mem64, xmm, xmm
	vcmpsd $7,%xmm14,%xmm6,%xmm2

# Tests for op xmm/mem64, xmm, xmm
	vaddsd %xmm14,%xmm6,%xmm2
	vdivsd %xmm14,%xmm6,%xmm2
	vmaxsd %xmm14,%xmm6,%xmm2
	vminsd %xmm14,%xmm6,%xmm2
	vmulsd %xmm14,%xmm6,%xmm2
	vsqrtsd %xmm14,%xmm6,%xmm2
	vsubsd %xmm14,%xmm6,%xmm2
	vcmpeqsd %xmm14,%xmm6,%xmm2
	vcmpltsd %xmm14,%xmm6,%xmm2
	vcmplesd %xmm14,%xmm6,%xmm2
	vcmpunordsd %xmm14,%xmm6,%xmm2
	vcmpneqsd %xmm14,%xmm6,%xmm2
	vcmpnltsd %xmm14,%xmm6,%xmm2
	vcmpnlesd %xmm14,%xmm6,%xmm2
	vcmpordsd %xmm14,%xmm6,%xmm2
	vcmpeq_uqsd %xmm14,%xmm6,%xmm2
	vcmpngesd %xmm14,%xmm6,%xmm2
	vcmpngtsd %xmm14,%xmm6,%xmm2
	vcmpfalsesd %xmm14,%xmm6,%xmm2
	vcmpneq_oqsd %xmm14,%xmm6,%xmm2
	vcmpgesd %xmm14,%xmm6,%xmm2
	vcmpgtsd %xmm14,%xmm6,%xmm2
	vcmptruesd %xmm14,%xmm6,%xmm2
	vcmpeq_ossd %xmm14,%xmm6,%xmm2
	vcmplt_oqsd %xmm14,%xmm6,%xmm2
	vcmple_oqsd %xmm14,%xmm6,%xmm2
	vcmpunord_ssd %xmm14,%xmm6,%xmm2
	vcmpneq_ussd %xmm14,%xmm6,%xmm2
	vcmpnlt_uqsd %xmm14,%xmm6,%xmm2
	vcmpnle_uqsd %xmm14,%xmm6,%xmm2
	vcmpord_ssd %xmm14,%xmm6,%xmm2
	vcmpeq_ussd %xmm14,%xmm6,%xmm2
	vcmpnge_uqsd %xmm14,%xmm6,%xmm2
	vcmpngt_uqsd %xmm14,%xmm6,%xmm2
	vcmpfalse_ossd %xmm14,%xmm6,%xmm2
	vcmpneq_ossd %xmm14,%xmm6,%xmm2
	vcmpge_oqsd %xmm14,%xmm6,%xmm2
	vcmpgt_oqsd %xmm14,%xmm6,%xmm2
	vcmptrue_ussd %xmm14,%xmm6,%xmm2

# Tests for op xmm/mem32, xmm, xmm
	vaddss %xmm14,%xmm6,%xmm2
	vdivss %xmm14,%xmm6,%xmm2
	vmaxss %xmm14,%xmm6,%xmm2
	vminss %xmm14,%xmm6,%xmm2
	vmulss %xmm14,%xmm6,%xmm2
	vrcpss %xmm14,%xmm6,%xmm2
	vrsqrtss %xmm14,%xmm6,%xmm2
	vsqrtss %xmm14,%xmm6,%xmm2
	vsubss %xmm14,%xmm6,%xmm2
	vcmpeqss %xmm14,%xmm6,%xmm2
	vcmpltss %xmm14,%xmm6,%xmm2
	vcmpless %xmm14,%xmm6,%xmm2
	vcmpunordss %xmm14,%xmm6,%xmm2
	vcmpneqss %xmm14,%xmm6,%xmm2
	vcmpnltss %xmm14,%xmm6,%xmm2
	vcmpnless %xmm14,%xmm6,%xmm2
	vcmpordss %xmm14,%xmm6,%xmm2
	vcmpeq_uqss %xmm14,%xmm6,%xmm2
	vcmpngess %xmm14,%xmm6,%xmm2
	vcmpngtss %xmm14,%xmm6,%xmm2
	vcmpfalsess %xmm14,%xmm6,%xmm2
	vcmpneq_oqss %xmm14,%xmm6,%xmm2
	vcmpgess %xmm14,%xmm6,%xmm2
	vcmpgtss %xmm14,%xmm6,%xmm2
	vcmptruess %xmm14,%xmm6,%xmm2
	vcmpeq_osss %xmm14,%xmm6,%xmm2
	vcmplt_oqss %xmm14,%xmm6,%xmm2
	vcmple_oqss %xmm14,%xmm6,%xmm2
	vcmpunord_sss %xmm14,%xmm6,%xmm2
	vcmpneq_usss %xmm14,%xmm6,%xmm2
	vcmpnlt_uqss %xmm14,%xmm6,%xmm2
	vcmpnle_uqss %xmm14,%xmm6,%xmm2
	vcmpord_sss %xmm14,%xmm6,%xmm2
	vcmpeq_usss %xmm14,%xmm6,%xmm2
	vcmpnge_uqss %xmm14,%xmm6,%xmm2
	vcmpngt_uqss %xmm14,%xmm6,%xmm2
	vcmpfalse_osss %xmm14,%xmm6,%xmm2
	vcmpneq_osss %xmm14,%xmm6,%xmm2
	vcmpge_oqss %xmm14,%xmm6,%xmm2
	vcmpgt_oqss %xmm14,%xmm6,%xmm2
	vcmptrue_usss %xmm14,%xmm6,%xmm2

# Tests for op xmm/mem32, xmm
	vcomiss %xmm14,%xmm6
	vucomiss %xmm14,%xmm6

# Tests for op imm8, xmm/mem32, xmm, xmm
	vcmpss $7,%xmm14,%xmm6,%xmm2