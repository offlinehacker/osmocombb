#!/bin/bash
tshark -Tfields -e gsm_sms.sms_text -i lo
