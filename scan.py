core0.JLinkScript 에서는

CORESIGHT_CoreBaseAddr = 0x80030000;
CORESIGHT_AddAP(0, CORESIGHT_APB_AP);
CORESIGHT_IndexAPBAPToUse = 0;

_PrepDAP();
_SelectAXIAP32();

v = _ReadViaAP(0x30313f30);
v |= 0x00000001;

_WriteViaAP(0x30313f30, v);

core1.JLinkScript 에서는

CORESIGHT_CoreBaseAddr = 0x80032000;
CORESIGHT_AddAP(0, CORESIGHT_APB_AP);
CORESIGHT_IndexAPBAPToUse = 0;

_PrepDAP();
_SelectAXIAP32();

v = _ReadViaAP(0x30313f30);
v |= 0x00000100;

_WriteViaAP(0x30313f30, v);

core2.JLinkScript 에서는

CORESIGHT_CoreBaseAddr = 0x80034000;
CORESIGHT_AddAP(0, CORESIGHT_APB_AP);
CORESIGHT_IndexAPBAPToUse = 0;

_PrepDAP();
_SelectAXIAP32();

v = _ReadViaAP(0x30313f30);
v |= 0x00010000;

_WriteViaAP(0x30313f30, v);

