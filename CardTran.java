package com.bilogicsys.controller.onelink.iso;

import static com.bilogicsys.controller.onelink.iso.SwitchServer.logger;
import com.bilogicsys.controller.hsm.*;
import com.bilogicsys.controller.pheft.ARPCGenerateResponse;
import com.bilogicsys.controller.pheft.ProtectHost;
import com.bilogicsys.controller.pheft.VerifyACVisaResponse;

/**
 * Description of the Class
 *
 * @author Haja Alavudeen
 * @created February 22, 2003
 */
public class CardTran extends Transaction implements Cryptable {

    private int error = -1;
    private String code = "";
    private boolean arqcProcess;

    private String track2;
    private String account;
    private String pin;
    private int zoneKeyIndex;
    private String zpk;
    private ICCData iccData = null;
    private VerifyACVisaResponse arqcGenResponse;
    private ARPCGenerateResponse arpcGenResponse;

    private boolean isARQCProcessed = false;
    private boolean isPinDataProcessed = false;

    private boolean isARPCTimeout = false;
    private boolean isARQCTimeout = false;

    public CardTran(Message message, int zoneKeyIndex, String track2, String account, String pin) {
        this(message, track2, account, pin);
        this.zoneKeyIndex = zoneKeyIndex;
    }

    public CardTran(Message message, String track2, String account, String pin) {
        super(message);
        this.track2 = track2;
        this.account = account;
        this.pin = pin;
        this.zpk = server.getParameter().getIWK().getKey();
    }

    public CardTran(Message message, String track2, String account, String pin, ICCData iccdata) {
        super(message);
        this.track2 = track2;
        this.account = account;
        this.pin = pin;
        this.zpk = server.getParameter().getIWK().getKey();
        this.iccData = iccdata;
    }

    public Command getCommand() {

        String hdr = server.getEncryptionService().getHeaderString();
        String zpkKeyScheme = "";
        int encLength = server.getParameter().getEncryptionLength(); // get the key length as a server parameter
        switch (encLength) {
            case 1:
                zpkKeyScheme = "";
                break;
            case 2:
                zpkKeyScheme = "U";
                break;
            case 3:
                zpkKeyScheme = "T";
                break;
            default:
                zpkKeyScheme = "";
                break;
        }

        // Data : ZPK + Pin Block + Format + AccountNumber
        String data = zpkKeyScheme + zpk + pin + "01" + Transaction.getPrimaryAccountNumberRight(account);
        Command command = new Command(Command.HC_TRANPIN_ZPK_LMK, hdr, data);
        logger.info(this.toString() + ", " + command.getExternalCommand());

        return command;
    }

    public void cryptResult(int error, String result) {
        this.error = error;
        code = result;
//        if(error != 0)	
        logger.info(this.toString() + ", Crypt result " + result + " error=" + error);
        message.cryptProcess(this);
    }

    public void cryptError() {
        message.cryptProcess(this);
    }

    public int getError() {
        return error;
    }

    public String getCode() {
        return code;
    }

    public String toString() {
        return ("CardTran, " + message.toString());
    }

    public boolean isARPCGenerated() {

        if (arpcGenResponse == null || isARPCTimeout) {
            return false;
        } else if (arpcGenResponse.getReturnCode() != 0) {
            return false;
        }

        return true;
    }

    public boolean isARQCVerified() {

        System.err.println("==============================isARQCVerified() method ====================");

        while (!arqcProcess) {
            // while Not ARQC Process Continue 
        }
        System.err.println("getReturnCode  ---" + arqcGenResponse.getReturnCode());
        System.err.println("arqcGenResponse  ---" + arqcGenResponse);
        System.err.println("isARQCTimeout  ---" + isARQCTimeout);
        if (arqcGenResponse == null || isARQCTimeout) {
            return false;
        }

        return arqcGenResponse.getReturnCode() == 0;
    }

    public int arqcGenResponseReturnCode() {
    	 System.err.println("==============================CardTran - > arqcGenResponseReturnCode() method ====================");
    	System.err.println(arqcGenResponse.getResponse());
        return arqcGenResponse.getReturnCode();
    }

    public int arpcGenResponseReturnCode() {
        return arpcGenResponse.getReturnCode();
    }

    public void processARQCData(ProtectHost protectHostARQC) {

        if (iccData != null) {
            System.err.println("======================= in processARQCData ============================");
            arqcGenResponse = iccData.processARQC(protectHostARQC, this);
        }
        arqcProcess = true;

    }

    public void processARPCData(ProtectHost protectHost, int[] arpcResponseCode) {
        if (iccData != null) {
            arpcGenResponse = iccData.processARPC(protectHost, arpcResponseCode, this);
        }
    }

    public int[] getIssuerAuthenticationData(int[] arpcResponseCode) {
        return iccData.getIssuerAuthenticationData(arpcGenResponse.getARPC(), arpcResponseCode);
    }

}
