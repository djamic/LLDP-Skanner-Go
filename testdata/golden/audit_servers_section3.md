## 3. Topologiya Sxemasi

```mermaid
graph TD
  VM_Windows_VMwarebr10_10_10_30["[VM] 🪟 Windows VMware<br>10.10.10.30"]
  ENDPOINT_VMwarebr172_20_9_121["[ENDPOINT] VMware<br>172.20.9.121"]
  VM_Linux_VMwarebr10_10_10_25["[VM] 🐧 Linux VMware<br>10.10.10.25"]
  ENDPOINT_VMwarebr172_20_7_22["[ENDPOINT] VMware<br>172.20.7.22"]
  VM_VMware_VM_VMwarebr10_10_10_23["[VM] 💻 VMware VM VMware<br>10.10.10.23"]
  VM_VMware_VM_VMwarebr10_10_10_24["[VM] 💻 VMware VM VMware<br>10.10.10.24"]
  ENDPOINT_VMwarebr172_20_6_211["[ENDPOINT] VMware<br>172.20.6.211"]
  ENDPOINT_VMwarebr195_158_2_214["[ENDPOINT] VMware<br>195.158.2.214"]
  VM_VMware_VM_VMwarebr172_20_13_243["[VM] 💻 VMware VM VMware<br>172.20.13.243"]
  ENDPOINT_VMwarebr195_158_2_218["[ENDPOINT] VMware<br>195.158.2.218"]
  VM_VMware_VM_VMwarebr10_10_10_31["[VM] 💻 VMware VM VMware<br>10.10.10.31"]
  VM_VMware_VM_VMwarebr10_10_10_31_2["[VM] 💻 VMware VM VMware<br>10.10.10.31"]
  VM_VMware_VM_VMwarebr172_20_6_247["[VM] 💻 VMware VM VMware<br>172.20.6.247"]
  ENDPOINT_VMwarebr10_10_10_4["[ENDPOINT] VMware<br>10.10.10.4"]
  ENDPOINT_VMwarebr195_158_2_211["[ENDPOINT] VMware<br>195.158.2.211"]
  VM_Windows_VMwarebr10_10_10_66["[VM] 🪟 Windows VMware<br>10.10.10.66"]
  VM_Windows_VMwarebr10_10_10_22["[VM] 🪟 Windows VMware<br>10.10.10.22"]
  HPbr172_20_254_247["HP<br>172.20.254.247"]
  A_Mobilbr172_20_230_50["A Mobil<br>172.20.230.50"]
  D_1br172_20_230_3["D - 1<br>172.20.230.3"]
  A_220br172_20_230_49["A 220<br>172.20.230.49"]
  HPEbr172_20_230_36["HPE<br>172.20.230.36"]
  F_9br172_20_240_12["F-9<br>172.20.240.12"]
  br172_20_230_81["<br>172.20.230.81"]
  HPEbr172_20_254_10["HPE<br>172.20.254.10"]
  HPEbr172_20_230_2["HPE<br>172.20.230.2"]
  B_3182br172_20_230_11["B-318/2<br>172.20.230.11"]
  HPEbr172_20_254_199["HPE<br>172.20.254.199"]
  A_3_Etajbr172_20_230_46["A 3 Etaj<br>172.20.230.46"]
  HPEbr172_20_230_82["HPE<br>172.20.230.82"]
  HPEbr172_20_230_43["HPE<br>172.20.230.43"]
  HPEbr172_20_253_11["HPE<br>172.20.253.11"]
  HPEbr172_20_253_10["HPE<br>172.20.253.10"]
  br172_20_230_76["<br>172.20.230.76"]
  HPEbr172_20_254_202["HPE<br>172.20.254.202"]
  HPEbr172_20_230_240["HPE<br>172.20.230.240"]
  HPEbr172_20_230_7["HPE<br>172.20.230.7"]
  B_3181br172_20_230_13["B-318/1<br>172.20.230.13"]
  HPEbr172_20_230_241["HPE<br>172.20.230.241"]
  HPEbr172_20_230_6["HPE<br>172.20.230.6"]
  TTJ_34br172_20_230_23["TTJ-3&4<br>172.20.230.23"]
  B_423br172_20_230_15["B-423<br>172.20.230.15"]
  MEDIA_MARKAZbr172_20_230_37["MEDIA MARKAZ<br>172.20.230.37"]
  HPEbr172_20_230_39["HPE<br>172.20.230.39"]
  A_332br172_20_230_8["A-332<br>172.20.230.8"]
  br172_20_254_203["<br>172.20.254.203"]
  C_424abr172_20_230_4["C 424/a<br>172.20.230.4"]
  HPEbr172_20_230_35["HPE<br>172.20.230.35"]
  HPEbr172_20_230_14["HPE<br>172.20.230.14"]
  F_2br172_20_240_14["F-2<br>172.20.240.14"]
  A_RRT_Kalidorbr172_20_230_42["A RRT Kalidor<br>172.20.230.42"]
  HPEbr172_20_230_41["HPE<br>172.20.230.41"]
  D_1_2br172_20_230_48["D 1-2<br>172.20.230.48"]
  B_3183br172_20_230_1["B-318/3<br>172.20.230.1"]
  HPEbr172_20_230_5["HPE<br>172.20.230.5"]
  HPEbr172_20_230_9["HPE<br>172.20.230.9"]
  VM_Windowsbr172_20_0_50["[VM] 🪟 Windows<br>172.20.0.50"]
  HPbr172_20_254_204["HP<br>172.20.254.204"]
  br172_20_230_253br172_20_7_227["<br>172.20.230.253<br>172.20.7.227"]
  BMC_Fujitsu_iRMCbr172_16_25_231["[BMC] Fujitsu iRMC<br>172.16.25.231"]
  VM_Windowsbr10_10_10_70["[VM] 🪟 Windows<br>10.10.10.70"]
  HPbr172_20_254_223["HP<br>172.20.254.223"]
  VM_Linuxbr10_10_10_69["[VM] 🐧 Linux<br>10.10.10.69"]
  Jamicbr172_20_254_226["Jamic<br>172.20.254.226"]
  E_209_2br172_20_230_34["E-209.2<br>172.20.230.34"]
  E205_48br172_20_230_31["E205-48<br>172.20.230.31"]
  E109br172_20_230_22["E109<br>172.20.230.22"]
  SNR_S2985G_48Tbr172_20_230_26["SNR-S2985G-48T<br>172.20.230.26"]
  SNR_S2985G_48Tbr172_20_230_28["SNR-S2985G-48T<br>172.20.230.28"]
  E102br172_20_230_27["E102<br>172.20.230.27"]
  SNR_S2985G_24TCbr172_20_230_25["SNR-S2985G-24TC<br>172.20.230.25"]
  E202_24br172_20_230_29["E202-24<br>172.20.230.29"]
  E_209br172_20_230_33["E-209<br>172.20.230.33"]
  SNR_S2985G_24TCbr172_20_230_83["SNR-S2985G-24TC<br>172.20.230.83"]
  E109_2br172_20_230_24["E109-2<br>172.20.230.24"]
  E205_24br172_20_230_32["E205-24<br>172.20.230.32"]
  F_31br172_20_240_10["F-3(1)<br>172.20.240.10"]
  F_42_28Pbr172_20_240_2["F-4(2)_28P<br>172.20.240.2"]
  F_32br172_20_240_11["F-3(2)<br>172.20.240.11"]
  F_72br172_20_240_7["F-7(2)<br>172.20.240.7"]
  F_71br172_20_240_6["F-7(1)<br>172.20.240.6"]
  F_61br172_20_240_8["F-6(1)<br>172.20.240.8"]
  F_1br172_20_240_13["F-1<br>172.20.240.13"]
  F_62br172_20_240_9["F-6(2)<br>172.20.240.9"]
  F_8br172_20_240_4["F-8<br>172.20.240.4"]
  F_5br172_20_240_5["F-5<br>172.20.240.5"]
  F_4_48Pbr172_20_240_1["F-4_48P<br>172.20.240.1"]
  F_4_glavniybr172_20_240_3["F-4-glavniy<br>172.20.240.3"]
  SNR_S2995G_24FXbr172_20_230_254["SNR-S2995G-24FX<br>172.20.230.254"]
  br172_20_230_77["<br>172.20.230.77"]
  br172_20_230_47["<br>172.20.230.47"]
  A_padval_SNRbr172_20_230_51["A_padval_SNR<br>172.20.230.51"]
  HYPERVISOR_VMware_ESXibr5_VMs_on_ge104brVMs_10_10_10_25_10_10_10_24_10_10_10_31_10_10_10_31_10_10_10_66["[HYPERVISOR] VMware ESXi<br>5 VMs on ge1/0/4<br>VMs: 10.10.10.25, 10.10.10.24, 10.10.10.31, 10.10.10.31, 10.10.10.66"]
  HYPERVISOR_VMware_ESXibr3_VMs_on_ge105brVMs_10_10_10_30_10_10_10_23_10_10_10_22["[HYPERVISOR] VMware ESXi<br>3 VMs on ge1/0/5<br>VMs: 10.10.10.30, 10.10.10.23, 10.10.10.22"]
  HYPERVISOR_VMware_ESXibr2_VMs_on_ge1032brVMs_172_20_9_121_195_158_2_214["[HYPERVISOR] VMware ESXi<br>2 VMs on ge1/0/32<br>VMs: 172.20.9.121, 195.158.2.214"]
  HYPERVISOR_VMware_ESXibr2_VMs_on_ge1032brVMs_172_20_13_243_172_20_6_247["[HYPERVISOR] VMware ESXi<br>2 VMs on ge1/0/32<br>VMs: 172.20.13.243, 172.20.6.247"]
  br172_20_230_44["<br>172.20.230.44"]
  HUAWEIbr172_20_254_249["HUAWEI<br>172.20.254.249"]
  D_1br172_20_230_3-- "TGE1/0/52 [T] 1G ↔ TGE1/0/49" -->HPEbr172_20_253_10
  D_1br172_20_230_3-- "TGE1/0/51 [T] 1G ↔ TGE1/0/52" -->D_1_2br172_20_230_48
  HPEbr172_20_254_10-- "GE1/0/48 [T] 1G ↔ GE1/0/47" -->HPEbr172_20_254_202
  HPEbr172_20_254_10-- "GE1/0/5 [T]" -->VM_Windowsbr10_10_10_70
  HPEbr172_20_254_10-- "GE1/0/4 [T]" -->VM_Linuxbr10_10_10_69
  HPEbr172_20_254_10-- "ge1/0/4" -->HYPERVISOR_VMware_ESXibr5_VMs_on_ge104brVMs_10_10_10_25_10_10_10_24_10_10_10_31_10_10_10_31_10_10_10_66
  HPEbr172_20_254_10-- "ge1/0/5" -->HYPERVISOR_VMware_ESXibr3_VMs_on_ge105brVMs_10_10_10_30_10_10_10_23_10_10_10_22
  HPEbr172_20_230_2-- "TGE1/0/51 [T] 1G ↔ " -->E205_48br172_20_230_31
  HPEbr172_20_230_2-- "TGE1/0/52 [T] 1G ↔ " -->E109br172_20_230_22
  HPEbr172_20_230_2-- "TGE1/0/50 [T] 1G ↔ " -->SNR_S2985G_24TCbr172_20_230_25
  HPEbr172_20_230_2-- "GE1/0/21 [T] 100M ↔ " -->SNR_S2985G_24TCbr172_20_230_83
  HPEbr172_20_230_2-- "TGE1/0/49 [T] 1G ↔ " -->SNR_S2995G_24FXbr172_20_230_254
  B_3182br172_20_230_11-- "GE1/0/48 [T] 1G ↔ B-318/2" -->B_3181br172_20_230_13
  HPEbr172_20_254_199-- "GE1/0/20 [T] ↔ " -->ENDPOINT_VMwarebr172_20_6_211
  HPEbr172_20_254_199-- "TGE1/0/52 [T] 4G ↔ TGE1/0/50" -->HPEbr172_20_254_202
  HPEbr172_20_254_199-- "ge1/0/32" -->HYPERVISOR_VMware_ESXibr2_VMs_on_ge1032brVMs_172_20_9_121_195_158_2_214
  A_3_Etajbr172_20_230_46-- "GE1/0/48 [T] 1G ↔ GE1/0/45" -->HPEbr172_20_253_10
  A_3_Etajbr172_20_230_46-- "GE1/0/7 [V1624] 100M ↔ " -->BMC_Fujitsu_iRMCbr172_16_25_231
  A_3_Etajbr172_20_230_46-- "GE1/0/47 [T] 1G ↔ " -->br172_20_230_47
  HPEbr172_20_253_11-- "TGE1/0/49 [T] 10G ↔ TGE1/0/49" -->br172_20_254_203
  HPEbr172_20_253_11-- "TGE1/0/51 [T] 1G ↔ GE1/0/28" -->HPbr172_20_254_204
  HPEbr172_20_253_11-- "GE1/0/25 [T] 1G ↔ GE1/0/28" -->HPbr172_20_254_223
  HPEbr172_20_253_11-- "GE1/0/26 [T] 1G ↔ " -->Jamicbr172_20_254_226
  HPEbr172_20_253_10-- "GE1/0/47 [T] 1G ↔ GE1/0/47" -->HPEbr172_20_253_11
  HPEbr172_20_254_202-- "TGE1/0/49 [T] 10G ↔ TGE1/0/50" -->br172_20_254_203
  HPEbr172_20_254_202-- "GE1/0/32 [T]" -->VM_Windowsbr172_20_0_50
  HPEbr172_20_254_202-- "ge1/0/32" -->HYPERVISOR_VMware_ESXibr2_VMs_on_ge1032brVMs_172_20_13_243_172_20_6_247
  HPEbr172_20_230_240-- "TGE1/0/52 [T] 4G ↔ " -->SNR_S2995G_24FXbr172_20_230_254
  HPEbr172_20_230_7-- "GE1/0/8 [T] 1G ↔ GE1/0/48" -->A_220br172_20_230_49
  HPEbr172_20_230_7-- "GE1/0/48 [T] 1G ↔ GE1/0/26" -->HPEbr172_20_253_10
  HPEbr172_20_230_7-- "GE1/0/19 [T] 1G ↔ GE1/0/47" -->A_RRT_Kalidorbr172_20_230_42
  B_3181br172_20_230_13-- "TGE1/0/49 [T] 1G ↔ B-318/1" -->HPEbr172_20_253_10
  B_3181br172_20_230_13-- "GE1/0/46 [T] 1G ↔ B318" -->B_423br172_20_230_15
  B_3181br172_20_230_13-- "GE1/0/43 [T] 1G ↔ B-318/1" -->HPEbr172_20_230_39
  B_3181br172_20_230_13-- "GE1/0/45 [T] 1G ↔ GE1/0/48" -->HPEbr172_20_230_14
  HPEbr172_20_230_241-- "TGE1/0/49 [T] 10G ↔ " -->SNR_S2995G_24FXbr172_20_230_254
  TTJ_34br172_20_230_23-- "TGE1/0/49 [T] 1G ↔ " -->F_4_glavniybr172_20_240_3
  MEDIA_MARKAZbr172_20_230_37-- "TGE1/0/49 [T] 1G ↔ " -->SNR_S2995G_24FXbr172_20_230_254
  A_332br172_20_230_8-- "GE1/0/26 [T] 1G ↔ GE1/0/20" -->A_Mobilbr172_20_230_50
  A_332br172_20_230_8-- "GE1/0/45 [T] 1G ↔ GE1/0/48" -->br172_20_230_81
  A_332br172_20_230_8-- "TGE1/0/49 [T] 1G ↔ TGE1/0/52" -->HPEbr172_20_253_10
  A_332br172_20_230_8-- "GE1/0/48 [T] 1G ↔ GE1/0/48" -->HPEbr172_20_230_9
  br172_20_254_203-- "GE1/0/15 [V26] ↔ " -->ENDPOINT_VMwarebr195_158_2_218
  br172_20_254_203-- "GE1/0/31 [V26] ↔ " -->ENDPOINT_VMwarebr195_158_2_211
  C_424abr172_20_230_4-- "TGE1/0/49 [T] 1G ↔ TGE1/0/52" -->HPEbr172_20_253_11
  C_424abr172_20_230_4-- "GE1/0/46 [T] 1G ↔ GE1/0/45" -->HPEbr172_20_230_41
  HPEbr172_20_230_35-- "GE1/0/47 [T] 1G ↔ GE1/0/48" -->HPEbr172_20_230_36
  HPEbr172_20_230_35-- "GE1/0/48 [T] 1G ↔ GE1/0/47" -->HPEbr172_20_230_41
  HPEbr172_20_230_41-- "GE1/0/43 [T] 1G ↔ GE1/0/48" -->HPEbr172_20_230_82
  B_3183br172_20_230_1-- "GE1/0/47 [T] 1G ↔ B-318/3" -->B_3181br172_20_230_13
  HPEbr172_20_230_5-- "GE1/0/47 [T] 1G ↔ GE1/0/48" -->HPEbr172_20_230_43
  HPEbr172_20_230_5-- "TGE1/0/49 [T] 1G ↔ TGE1/0/51" -->HPEbr172_20_253_10
  HPEbr172_20_230_5-- "GE1/0/48 [T] 1G ↔ GE1/0/48" -->HPEbr172_20_230_6
  br172_20_230_253br172_20_7_227-- "Port28 ↔ TGE1/0/51" -->HPEbr172_20_254_202
  E205_48br172_20_230_31-- "Eth1/0/48 [T] 1G ↔ " -->E205_24br172_20_230_32
  E109br172_20_230_22-- "Eth1/0/51 [T] 1G ↔ " -->E109_2br172_20_230_24
  E102br172_20_230_27-- "Eth1/0/24 1G ↔ " -->SNR_S2985G_48Tbr172_20_230_28
  E102br172_20_230_27-- "Eth1/0/28 1G ↔ " -->SNR_S2995G_24FXbr172_20_230_254
  SNR_S2985G_24TCbr172_20_230_25-- "Eth1/0/24 1G ↔ " -->SNR_S2985G_48Tbr172_20_230_26
  E202_24br172_20_230_29-- "Eth1/0/28 1G ↔ " -->SNR_S2995G_24FXbr172_20_230_254
  E_209br172_20_230_33-- "Eth1/0/1 [T] 1G ↔ " -->E_209_2br172_20_230_34
  E_209br172_20_230_33-- "Eth1/0/28 [T] 1G ↔ " -->SNR_S2995G_24FXbr172_20_230_254
  F_31br172_20_240_10-- "Eth1/0/23 1G ↔ " -->F_32br172_20_240_11
  F_71br172_20_240_6-- "Eth1/0/23 1G ↔ " -->F_72br172_20_240_7
  F_61br172_20_240_8-- "Eth1/0/23 1G ↔ " -->F_62br172_20_240_9
  F_4_48Pbr172_20_240_1-- "Eth1/0/47 [T] 1G ↔ " -->F_42_28Pbr172_20_240_2
  F_4_48Pbr172_20_240_1-- "Eth1/0/52 [T] 1G ↔ " -->F_4_glavniybr172_20_240_3
  F_4_glavniybr172_20_240_3-- "Eth1/0/24 [T] 1G ↔ TGE1/0/52" -->F_9br172_20_240_12
  F_4_glavniybr172_20_240_3-- "Eth1/0/10 [T] 1G ↔ TGE1/0/52" -->F_2br172_20_240_14
  F_4_glavniybr172_20_240_3-- "Eth1/0/12 [T] 1G ↔ " -->F_31br172_20_240_10
  F_4_glavniybr172_20_240_3-- "Eth1/0/20 [T] 1G ↔ " -->F_71br172_20_240_6
  F_4_glavniybr172_20_240_3-- "Eth1/0/18 [T] 1G ↔ " -->F_61br172_20_240_8
  F_4_glavniybr172_20_240_3-- "Eth1/0/8 [T] 1G ↔ " -->F_1br172_20_240_13
  F_4_glavniybr172_20_240_3-- "Eth1/0/22 [T] 1G ↔ " -->F_8br172_20_240_4
  F_4_glavniybr172_20_240_3-- "Eth1/0/14 [T] 1G ↔ " -->F_5br172_20_240_5
  SNR_S2995G_24FXbr172_20_230_254-- "Eth1/0/9 [T] 1G ↔ GE1/0/28" -->HPbr172_20_254_247
  SNR_S2995G_24FXbr172_20_230_254-- "Eth1/0/1 [T] 1G ↔ GE1/0/25" -->HPEbr172_20_254_202
  SNR_S2995G_24FXbr172_20_230_254-- "Eth1/0/25 [T] 1G ↔ " -->F_4_glavniybr172_20_240_3
  br172_20_230_47-- "Eth1/0/25 [MAC-REF] ↔ " -->br172_20_230_253br172_20_7_227
  A_padval_SNRbr172_20_230_51-- "Eth1/0/28 1G ↔ " -->SNR_S2995G_24FXbr172_20_230_254
  HYPERVISOR_VMware_ESXibr5_VMs_on_ge104brVMs_10_10_10_25_10_10_10_24_10_10_10_31_10_10_10_31_10_10_10_66-- "vNIC" -->VM_Linux_VMwarebr10_10_10_25
  HYPERVISOR_VMware_ESXibr5_VMs_on_ge104brVMs_10_10_10_25_10_10_10_24_10_10_10_31_10_10_10_31_10_10_10_66-- "vNIC" -->VM_VMware_VM_VMwarebr10_10_10_24
  HYPERVISOR_VMware_ESXibr5_VMs_on_ge104brVMs_10_10_10_25_10_10_10_24_10_10_10_31_10_10_10_31_10_10_10_66-- "vNIC" -->VM_VMware_VM_VMwarebr10_10_10_31
  HYPERVISOR_VMware_ESXibr5_VMs_on_ge104brVMs_10_10_10_25_10_10_10_24_10_10_10_31_10_10_10_31_10_10_10_66-- "vNIC" -->VM_VMware_VM_VMwarebr10_10_10_31_2
  HYPERVISOR_VMware_ESXibr5_VMs_on_ge104brVMs_10_10_10_25_10_10_10_24_10_10_10_31_10_10_10_31_10_10_10_66-- "vNIC" -->VM_Windows_VMwarebr10_10_10_66
  HYPERVISOR_VMware_ESXibr3_VMs_on_ge105brVMs_10_10_10_30_10_10_10_23_10_10_10_22-- "vNIC" -->VM_Windows_VMwarebr10_10_10_30
  HYPERVISOR_VMware_ESXibr3_VMs_on_ge105brVMs_10_10_10_30_10_10_10_23_10_10_10_22-- "vNIC" -->VM_VMware_VM_VMwarebr10_10_10_23
  HYPERVISOR_VMware_ESXibr3_VMs_on_ge105brVMs_10_10_10_30_10_10_10_23_10_10_10_22-- "vNIC" -->VM_Windows_VMwarebr10_10_10_22
  HYPERVISOR_VMware_ESXibr2_VMs_on_ge1032brVMs_172_20_9_121_195_158_2_214-- "vNIC" -->ENDPOINT_VMwarebr172_20_9_121
  HYPERVISOR_VMware_ESXibr2_VMs_on_ge1032brVMs_172_20_9_121_195_158_2_214-- "vNIC" -->ENDPOINT_VMwarebr195_158_2_214
  HYPERVISOR_VMware_ESXibr2_VMs_on_ge1032brVMs_172_20_13_243_172_20_6_247-- "vNIC" -->VM_VMware_VM_VMwarebr172_20_13_243
  HYPERVISOR_VMware_ESXibr2_VMs_on_ge1032brVMs_172_20_13_243_172_20_6_247-- "vNIC" -->VM_VMware_VM_VMwarebr172_20_6_247
  HUAWEIbr172_20_254_249-- "GE0/0/14 [MAC-REF] ↔ " -->TTJ_34br172_20_230_23
  style VM_Windows_VMwarebr10_10_10_30 fill:#9C27B0,stroke:#7B1FA2,color:#fff
  style ENDPOINT_VMwarebr172_20_9_121 fill:#9C27B0,stroke:#7B1FA2,color:#fff
  style VM_Linux_VMwarebr10_10_10_25 fill:#9C27B0,stroke:#7B1FA2,color:#fff
  style ENDPOINT_VMwarebr172_20_7_22 fill:#9C27B0,stroke:#7B1FA2,color:#fff
  style VM_VMware_VM_VMwarebr10_10_10_23 fill:#9C27B0,stroke:#7B1FA2,color:#fff
  style VM_VMware_VM_VMwarebr10_10_10_24 fill:#9C27B0,stroke:#7B1FA2,color:#fff
  style ENDPOINT_VMwarebr172_20_6_211 fill:#9C27B0,stroke:#7B1FA2,color:#fff
  style ENDPOINT_VMwarebr195_158_2_214 fill:#9C27B0,stroke:#7B1FA2,color:#fff
  style VM_VMware_VM_VMwarebr172_20_13_243 fill:#9C27B0,stroke:#7B1FA2,color:#fff
  style ENDPOINT_VMwarebr195_158_2_218 fill:#9C27B0,stroke:#7B1FA2,color:#fff
  style VM_VMware_VM_VMwarebr10_10_10_31 fill:#9C27B0,stroke:#7B1FA2,color:#fff
  style VM_VMware_VM_VMwarebr10_10_10_31_2 fill:#9C27B0,stroke:#7B1FA2,color:#fff
  style VM_VMware_VM_VMwarebr172_20_6_247 fill:#9C27B0,stroke:#7B1FA2,color:#fff
  style ENDPOINT_VMwarebr10_10_10_4 fill:#9C27B0,stroke:#7B1FA2,color:#fff
  style ENDPOINT_VMwarebr195_158_2_211 fill:#9C27B0,stroke:#7B1FA2,color:#fff
  style VM_Windows_VMwarebr10_10_10_66 fill:#9C27B0,stroke:#7B1FA2,color:#fff
  style VM_Windows_VMwarebr10_10_10_22 fill:#9C27B0,stroke:#7B1FA2,color:#fff
  style HPbr172_20_254_247 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style A_Mobilbr172_20_230_50 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style D_1br172_20_230_3 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style A_220br172_20_230_49 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style HPEbr172_20_230_36 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style F_9br172_20_240_12 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style br172_20_230_81 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style HPEbr172_20_254_10 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style HPEbr172_20_230_2 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style B_3182br172_20_230_11 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style HPEbr172_20_254_199 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style A_3_Etajbr172_20_230_46 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style HPEbr172_20_230_82 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style HPEbr172_20_230_43 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style HPEbr172_20_253_11 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style HPEbr172_20_253_10 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style br172_20_230_76 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style HPEbr172_20_254_202 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style HPEbr172_20_230_240 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style HPEbr172_20_230_7 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style B_3181br172_20_230_13 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style HPEbr172_20_230_241 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style HPEbr172_20_230_6 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style TTJ_34br172_20_230_23 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style B_423br172_20_230_15 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style MEDIA_MARKAZbr172_20_230_37 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style HPEbr172_20_230_39 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style A_332br172_20_230_8 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style br172_20_254_203 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style C_424abr172_20_230_4 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style HPEbr172_20_230_35 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style HPEbr172_20_230_14 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style F_2br172_20_240_14 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style A_RRT_Kalidorbr172_20_230_42 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style HPEbr172_20_230_41 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style D_1_2br172_20_230_48 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style B_3183br172_20_230_1 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style HPEbr172_20_230_5 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style HPEbr172_20_230_9 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style VM_Windowsbr172_20_0_50 fill:#9C27B0,stroke:#7B1FA2,color:#fff
  style HPbr172_20_254_204 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style br172_20_230_253br172_20_7_227 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style BMC_Fujitsu_iRMCbr172_16_25_231 fill:#FF6F00,stroke:#E65100,color:#fff
  style VM_Windowsbr10_10_10_70 fill:#9C27B0,stroke:#7B1FA2,color:#fff
  style HPbr172_20_254_223 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style VM_Linuxbr10_10_10_69 fill:#9C27B0,stroke:#7B1FA2,color:#fff
  style Jamicbr172_20_254_226 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style E_209_2br172_20_230_34 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style E205_48br172_20_230_31 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style E109br172_20_230_22 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style SNR_S2985G_48Tbr172_20_230_26 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style SNR_S2985G_48Tbr172_20_230_28 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style E102br172_20_230_27 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style SNR_S2985G_24TCbr172_20_230_25 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style E202_24br172_20_230_29 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style E_209br172_20_230_33 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style SNR_S2985G_24TCbr172_20_230_83 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style E109_2br172_20_230_24 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style E205_24br172_20_230_32 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style F_31br172_20_240_10 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style F_42_28Pbr172_20_240_2 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style F_32br172_20_240_11 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style F_72br172_20_240_7 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style F_71br172_20_240_6 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style F_61br172_20_240_8 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style F_1br172_20_240_13 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style F_62br172_20_240_9 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style F_8br172_20_240_4 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style F_5br172_20_240_5 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style F_4_48Pbr172_20_240_1 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style F_4_glavniybr172_20_240_3 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style SNR_S2995G_24FXbr172_20_230_254 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style br172_20_230_77 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style br172_20_230_47 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style A_padval_SNRbr172_20_230_51 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style HYPERVISOR_VMware_ESXibr5_VMs_on_ge104brVMs_10_10_10_25_10_10_10_24_10_10_10_31_10_10_10_31_10_10_10_66 fill:#26C6DA,stroke:#0097A7,color:#fff
  style HYPERVISOR_VMware_ESXibr3_VMs_on_ge105brVMs_10_10_10_30_10_10_10_23_10_10_10_22 fill:#26C6DA,stroke:#0097A7,color:#fff
  style HYPERVISOR_VMware_ESXibr2_VMs_on_ge1032brVMs_172_20_9_121_195_158_2_214 fill:#26C6DA,stroke:#0097A7,color:#fff
  style HYPERVISOR_VMware_ESXibr2_VMs_on_ge1032brVMs_172_20_13_243_172_20_6_247 fill:#26C6DA,stroke:#0097A7,color:#fff
  style br172_20_230_44 fill:#4A90E2,stroke:#2A6FC2,color:#fff
  style HUAWEIbr172_20_254_249 fill:#4A90E2,stroke:#2A6FC2,color:#fff

```

**Izoh (rang kodlari):**

| Rang | Turi |
|---|---|
| 🔵 | Switch |
| 🔴 | Router |
| 💠 | Hypervisor |
| 🟣 | VM |
| 🟧 | BMC/iLO |
| 🔶 | Server |

