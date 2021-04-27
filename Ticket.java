package com.example.auth.ticket;

import android.os.Build;
import android.support.annotation.RequiresApi;
import android.util.Log;

import com.example.auth.app.ulctools.Commands;
import com.example.auth.app.ulctools.Reader;
import com.example.auth.app.ulctools.Utilities;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Ticket {

    private static final byte[] defaultAuthenticationKey = "BREAKMEIFYOUCAN!".getBytes();// 16-byte key
    private static final byte[] newAuthenticationKey = "THISKEYISHARD!!!".getBytes();// 16-byte key
    private static final byte[] hmacKey = "SECRETMASTERKEY!".getBytes(); // min 16-byte key
    private byte[] authenticationKey = defaultAuthenticationKey;// 16-byte key

    public static byte[] data = new byte[192]; // the amount of data on the card 4*48

    private static Utilities utils;
    private static Commands ul;

    private Boolean isValid = false;
    private int remainingUses = 0;
    private long expiryTime = 0;

    private static String infoToShow; // Use this to show messages

    // own global vars added from here
    private String applicationTag = "ride"; // max length: 4 bytes
    private final String versionNumber = "1.10"; // max length: 4 bytes
    private final long maxValidity = 15555500; //TODO: this is unused at the moment
    private final long timeToAdd = 60; // seconds to extend validity with (based on current time)
    private final int ticketsToAddPerTime = 5;
    private static final byte[] AUTH0 = { (byte) 4, (byte) 0, (byte) 0, (byte) 0 };
    private static final byte[] AUTH1 = { (byte) 0, (byte) 0, (byte) 0, (byte) 0 }; //value of zero ==> read + write restricted

    /** Create a new ticket */
    public Ticket() throws GeneralSecurityException {
        ul = new Commands();
        utils = new Utilities(ul);
    }

    /** After validation, get ticket status: was it valid or not? */
    public boolean isValid() {
        return isValid;
    }

    /** After validation, get the number of remaining uses */
    public int getGlobalRemainingUses() {
        return remainingUses;
    }

    /** After validation, get the expiry time */
    public long getExpiryTime() {
        return expiryTime;
    }

    /** After validation/issuing, get information */
    public static String getInfoToShow() {
        String tmp = infoToShow;
        infoToShow = "";
        return tmp;
    }

    /**
     * TODO: do I want to lock non used pages?
     * TODO: do I want to lock the password!!!
     * TODO: update these description!
     *
     * Some general design rules:
     * 1-3: do not touch: UID resides here!
     * 4: Store application tag here
     * 5: Store version number
     * 6: Initial Ride Counter (4 bytes = 16bit (see OTP))
     * 7: Ride counter
     * 8-9: Validity date
     * 10-11: Expiry date
     * 12: MAC_1 (truncated)
     * 13: MAC_2 (truncated)
     * 14-39: empty/unused
     * 40: lock bits
     * 41: 16-bit one-way counter
     * 42: auth0
     * 43: auth1
     * 44-47: password
     *
     * Design principle: make it safe
     */

    /**
     * Issue new tickets
     *
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public boolean issue(int daysValid, int uses) throws GeneralSecurityException, UnsupportedEncodingException {
        byte[] UID = readUID();
        int macVersion;

        //return startWithNewCard(); // if you want to reset card to fresh state
        authenticationKey = getUniquePassword(UID, newAuthenticationKey);
        // Authenticate for first time (use the default authenticationKey here!
        if (utils.authenticate(defaultAuthenticationKey)) { // no unique password has been set yet
            Log.e("Issue", "This is the first time that a user tries to use this card!");
            if (!writeNewPassword(authenticationKey) || !issueNewCard()) { // TODO: maybe throw an error here??
                return false;
            }
            if (!setAUTHBits()){
                return false;
            }
            infoToShow = "I successfully issued the card!";
        } else if (utils.authenticate(authenticationKey)) { // there already exists a unique password
            if (needToIssue() || getRemainingUses() <= 0) {
                Log.d("Issue","We will issue the card now!");
                if (!utils.eraseMemory() || !issueNewCard()) {
                    infoToShow = "Issuing the card has failed";
                    return false;
                }
                macVersion = 1;
                infoToShow = "Succesfully issued the card!";
            } else {
                Log.d("Issue","We will top up the card now!");
                if (!checkCredibility(5) || !topUpCard(ticketsToAddPerTime)) {
                    infoToShow = "Topping up the card failed!";
                    return false;
                }
                if (isFirstRide()) macVersion = 1;
                else macVersion = 2;

                infoToShow = "Succesfully topped up the card";
            }
            if (!writeMAC(macVersion)) {
                infoToShow = "Issuing the card has failed!";
                return false;
            }
        }
        // throw error otherwise
        else {
            Log.e("Issue", "authentication failed!");
            byte[] failurePass = new byte[4 * 4];
            boolean res = utils.readPages(44, 4, failurePass, 0);
            Log.e("Wrong password used:", new String(failurePass));
            infoToShow = "Issuing/Topping up the card failed!";
            return false;
        }
        //TODO: check this in a bit more detail!!
        if (!Reader.setAuthKey(bytesToHex(firstHalfOfByteArray(authenticationKey)))) {
            Log.e("Issue", "Setting new password failed!");
            return false;
        }
        return true;
    }

    /**
     * Use ticket once
     *
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public boolean use() throws GeneralSecurityException {
        isValid = false;

        // Authenticate
        if (utils.authenticate(defaultAuthenticationKey)) {
            infoToShow = "You have to issue tickets first!";
            return false;
        } else if (utils.authenticate(getUniquePassword(readUID(), newAuthenticationKey))) {
            if(isFirstRide()){
                Log.d("use","This is the first ride!");
                if (System.currentTimeMillis() > getLatestValidityTime()){
                    infoToShow = "Using ticket failed!";
                    Log.e("use","Card has to be issued again (validity time expired!");
                    return false;
                }
                if(!checkMacCode(1)){
                    Log.e("use","mac code for first ride ticket is invalid!!");
                    return false;
                }
                if( !setExpiryDate(timeToAdd) || !writeMAC(2) ){
                    infoToShow = "Using ticket for first time failed!";
                    return false;
                }
            }
            if (!checkCredibility(6) || !checkMacCode(2) || !removeRide()) {
                infoToShow = "Using ticket failed!";
                //TODO maybe add statement that all tickets are used! But again maybe safety?
                return false;
            }
            infoToShow = "Number of rides left:" + getRemainingUses();
        } else {
            Utilities.log("Authentication failed in use()", true);
            Log.e("Use", "Authentication failed!");
            infoToShow = "Using ticket failed!";
            return false;
        }
        isValid = true;
        return true;
    }

    // #########################################################################
    // ################################## Read the UID #########################
    // #########################################################################
    // trying to read the UID
    // it's the first 9 bytes: looks as follows (see specification document)
    // |012x|0123|x
    // The x's represent control bits to check the correctness of the UID
    private byte[] readUID() {
        byte[] uid = new byte[12];
        utils.readPages(0, 3, uid, 0);
        uid = Arrays.copyOf(uid, 9);
        return uid;
    }

    // #######################################################################
    // ########################### Unique password ###########################
    // #######################################################################
    //sha-256 has a length of 32 bytes ==> have to take half of it to fit 4*4 bytes available
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    private byte[] getUniquePassword(byte[] UID, byte[] masterPassword) throws NoSuchAlgorithmException {
        byte[] originalString = addTwoByteArrays(masterPassword, UID);
        try {
            final MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(originalString);
            return firstHalfOfByteArray(digest.digest());
        } catch (Exception e) {
            e.printStackTrace();
            return (originalString);
        }
    }

    /**
     * Write the first bytes of the generated password to registers 44-47 on the NFC
     * chip
     *
     * @param password
     * @return
     */
    private boolean writeNewPassword(byte[] password) {
        if (!utils.writePages(password, 0, 44, 4)) {
            Log.e("writeNewPassword", "Password could not be written");
            return false;
        }
        Log.d("writeNewPassword", "Password succesfully written!");
        return true;
    }

    private boolean setAUTHBits() {
        if (!utils.writePages(AUTH0, 0, 42, 1) || !utils.writePages(AUTH1, 0, 43, 1)) {
            Log.e("setAUTHBits", "Setting the auth bits failed!");
            return false;
        }
        Log.d("setAUTHBits", "authbits have been successfully set!");
        return true;
    }

    // #######################################################################
    // ########################### Issue new card ############################
    // #######################################################################
    private boolean issueNewCard() {
        if (!checkIfIssuable() || !setVersionNumber(versionNumber.getBytes()) || !setApplicationTag(applicationTag.getBytes())
                || !startWithFiveRides() || !setValidityTimer(timeToAdd)) {
            Log.d("issueNewCard", "Issuing the card has failed!");
            return false;
        }
        return true;
    }

    private boolean needToIssue(){
        long expiryTime = getLatestExpiryTime();
        long validityTime = getLatestValidityTime();
        long maxTime;
        if (expiryTime != 0) maxTime = Math.min(expiryTime, validityTime);
        else maxTime = validityTime;

        return System.currentTimeMillis() > maxTime;
    }

    // add five rides & change the validity time!
    private boolean topUpCard(int numberOfAdditionalRides) {
        if (isFirstRide()){
            if (!setValidityTimer(timeToAdd)){
                Log.e("topUpCard","Setting New Validity time failed!");
                return false;
            }
        } else {
            if (! setExpiryDate(timeToAdd)){
                Log.e("topUpCard","Setting new Expiry time failed!");
                return false;
            }
        }
        if (!addFiveRides()) {
            Log.e("topUpCard", "Adding five rides failed!");
            return false;
        }
        Log.d("topUpCard", "Succesfully topped up the card!");
        return true;
    }

    /**
     *
     * @param applicationTag Can be 4 bytes at most!!!
     */
    private boolean setApplicationTag(byte[] applicationTag) {
        if (applicationTag.length > 4 || !utils.writePages(createLengthOfModulOFour(applicationTag), 0, 4, 1)) {
            Log.e("setApplicationTag", "Writing the applicationtag failed!");
            return false;
        }
        Log.d("setApplicationTag", "Succesfully written application tag!");
        return true;
    }

    /**
     *
     * @param versionNumber Can be 4 bytes long at most!
     *                      Format: x.x
     */
    private boolean setVersionNumber(byte[] versionNumber) {
        if (versionNumber.length > 4 || !utils.writePages(createLengthOfModulOFour(versionNumber), 0, 5, 1)) {
            Log.e("setVersionNumber", "Writing the version number failed!");
            return false;
        }
        Log.d("setVersionNumber", "Succesfully written version number!");
        return true;
    }

    private boolean startWithFiveRides() {
        int currentRideCounter_int = getCurrentRidesCounter();
        if (currentRideCounter_int < 0){
            return false;
        }
        Log.v("previousAmountOfRides", String.valueOf(currentRideCounter_int));
        int newRideCounter_int = currentRideCounter_int + ticketsToAddPerTime;
        Log.v("newAmountOfRides", String.valueOf(newRideCounter_int));
        if (!utils.writePages(createLengthOfModulOFour(leIntToByteArray(currentRideCounter_int)), 0, 6, 1)) {
            Log.e("startWithFiveRides","Setting original amounts of tickets failed");
            return false;
        }
        if(!utils.writePages(createLengthOfModulOFour(leIntToByteArray(newRideCounter_int)),0,7,1)){
            Log.e("startWithFiveRides", "Setting initial tickets to 5 failed!");
            return false;
        }
        Log.d("test","values " + getNumberOfRides());
        Log.d("startWithFiveRides", "5 rides have been given to the card!");
        return true;
    }

    private boolean addFiveRides() {
        int AmountOfRides = getNumberOfRides();
        if (AmountOfRides < 0){
            return false;
        }
        Log.v("previousAmountOfRides:", String.valueOf(AmountOfRides));
        AmountOfRides += 5;
        Log.v("newAmountOfRides:", String.valueOf(AmountOfRides));
        byte[] message = leIntToByteArray(AmountOfRides);
        if (!utils.writePages(createLengthOfModulOFour(message), 0, 7, 1)) { // note modulo not nessecary actually because message always has length of 4!
            Log.d("addFiveRides", "Writing maxRides page failed!");
            return false;
        }
        return true;
    }

    // date is 8 bytes long in Java ==> need two blocks
    // Note: validity data = for bookkeeping purposes!
    // In this case: give validity timer of 2 minutes!
    private boolean setValidityTimer(long timeToAdd) {
        long validityDate = System.currentTimeMillis() + 3*timeToAdd*1000;
        if (!utils.writePages(createLengthOfModulOFour(leLongToByteArray(validityDate)), 0,8 , 2)) {
            Log.e("setValidityTimer", "Writing a validity timer failed!");
            return false;
        }
        Log.d("setValidityTimer", "Succesfully set the validity timer!");
        return true;
    }

    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    private boolean writeMAC(int version) throws GeneralSecurityException {
        byte[] MACPassword = getUniquePassword(readUID(), hmacKey);
        int pagesToWrite;
        int pageNumber;

        if (version == 1){
            pagesToWrite = 4;
            pageNumber = 12;
        }
        else { pagesToWrite = 6; pageNumber = 13;}
        byte[] dataToEncode = new byte[4*pagesToWrite];
        if (!utils.readPages(6, pagesToWrite, dataToEncode, 0)) {
            Log.e("writeMac", "Error while reading 'sensitive' info");
            return false;
        }
        byte[] macEncoding = createMac(dataToEncode, MACPassword);
        if (!utils.writePages(macEncoding, 0, pageNumber, 1)) {
            Log.e("writeMAC", "Error while writing MAC to nfc card.");
            return false;
        }
        Log.d("writeMac", "Mac has been successfully written!");
        return true;
    }

    private byte[] createMac(byte[] dataToEncode, byte[] macPassword) throws GeneralSecurityException {
        TicketMac macAlgorithm = new TicketMac();
        macAlgorithm.setKey(macPassword);
        byte[] longMAC = macAlgorithm.generateMac(dataToEncode);// sha1 hmac is size 160 bits = 20 bytes ==> 5 blocks
        return Arrays.copyOf(longMAC, 4); // new length = 4 bytes
    }

    private int getCurrentRidesCounter() {
        byte[] rideCounter_bytes = new byte[4];
        if (!utils.readPages(41, 1, rideCounter_bytes, 0)) {
            Log.e("getCurrentRidesCounter", "Reading current amount of used rides failed!");
            return -1;
        }
        return byteArrayToLeInt(rideCounter_bytes);
    }

    private int getNumberOfRides() {
        byte[] maxRideCounter_byte = new byte[4];
        if (!utils.readPages(7, 1, maxRideCounter_byte, 0)) {
            Log.e("getCurrentRidesCounter", "Reading the maximal amount of allowed rides failed!");
            return -1;
        }
        return byteArrayToLeInt(maxRideCounter_byte);
    }

    private int getInitialNumberOfRides() {
        byte[] rideCounter_bytes = new byte[4];
        if (!utils.readPages(6, 1, rideCounter_bytes, 0)) {
            Log.e("getCurrentRidesCounter", "Reading current amount of used rides failed!");
            return -1;
        }
        return byteArrayToLeInt(rideCounter_bytes);
    }

    private boolean isFirstRide(){
        int initialNumberOfRides = getInitialNumberOfRides();
        int currentRidesCounter = getCurrentRidesCounter();
        if (initialNumberOfRides >= 0 && currentRidesCounter >= 0 && initialNumberOfRides == currentRidesCounter){
            return true;
        }
        return false;
    }

    private boolean checkIfIssuable(){
        if (Math.max(getNumberOfRides(),getCurrentRidesCounter()) + 5 >= Math.pow(2, 16)){
            Log.e("checkIfIssuable","Counter will surpass a safe limit!");
            return false;
        }
        if (!checkLockBytes(2, 2, 4) || !checkLockBytes(40,3,4)){
            return false;
        }
        Log.d("checkIfIsuable","Card is issuable!");
        return true;
    }

    private boolean checkLockBytes(int pageToRead, int start, int end){
        byte[] lockbytes = new byte[4];
        if (!utils.readPages(pageToRead,1,lockbytes, 0)){
            Log.e("checkIfIssuable","Reading lockbytes failed!");
            return false;
        }
        byte[] specifiedBytes = Arrays.copyOfRange(lockbytes, start, end);
        if( byteArrayToLeInt(createLengthOfModulOFour(specifiedBytes)) != 0){
            Log.e("checkIfIssuable","Lock bits (block " + String.valueOf(pageToRead) + ") set...");
            return false;
        }
        return true;
    }

    // #######################################################################
    // ########################### Reset Card ################################
    // #######################################################################
    private boolean startWithNewCard() {
        if (!writeNewPassword(defaultAuthenticationKey)) {
            Log.e("defaultPasswordReset", new String(defaultAuthenticationKey));
            return false;
        }
        return utils.eraseMemory();
    }

    // #######################################################################
    // ########################### Use ticket  ###############################
    // #######################################################################
    // want to edit page 41, first two bytes: xx..
    // from the docs: It is recommended to protect the access to the counter functionality by authentication
    // why?
    // -1 indicates sth went wrong!
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    private boolean removeRide() throws GeneralSecurityException {
        // check validity of ticket first
        if (!checkTimer())
            return false;
        // only then decrement rides
        byte[] rideCounter_bytes = leIntToByteArray(1);
        if (getRemainingUses() <= 0) {
            Log.e("removeRide", "No more rides left!");
            return false;
        }
        if (!utils.writePages(rideCounter_bytes, 0, 41, 1)) {
            Log.e("removeRide", "Writing new unique counter failed!");
            return false;
        }
        remainingUses = getRemainingUses();
        Log.d("removeRide:", "Removed one valid ride!");

        //TODO: maybe check time of last issued ticket as well? But not really sure how to implement that securely though...
        return true;
    }

    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    private boolean checkMacCode(int version) throws GeneralSecurityException {
        byte[] readMac = new byte[4];
        int pagesToRead;
        int pageNumber;
        if (version == 1){
            pagesToRead = 4;
            pageNumber = 12;
        }
        else { pagesToRead = 6; pageNumber = 13;}
        byte[] dataToEncode = new byte[4*pagesToRead];
        byte[] MacPassword = getUniquePassword(readUID(), hmacKey);

        if (!utils.readPages(6, pagesToRead, dataToEncode, 0)) {
            Log.e("checkMacCode", "Error while reading 'sensitive' info");
            return false;
        }
        byte[] computedMac = createMac(dataToEncode,MacPassword);

        if (!utils.readPages(pageNumber, 1, readMac, 0)) {
            Log.e("checkMacCode", "reading the mac failed!");
            return false;
        }
        if (!Arrays.equals(readMac, computedMac)) {
            Log.e("checkMacCode", "Computed and read mac are not equal!, page: " + pageNumber);
            return false;
        }
        Log.d("checkMacCode", "Succesfully verified and matched the mac code! (page: " + pageNumber + ")");
        return true;
    }


    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    private boolean checkTimer() throws GeneralSecurityException {
        long currentTime = System.currentTimeMillis();
        expiryTime = getLatestExpiryTime();
        if (expiryTime == -1) {
            return false;
        }
        if (currentTime > expiryTime) {
            Log.e("Checktime", "Validity of ticket has been surpassed!");
            return false;
        }
        return true;
    }

    private long getLatestValidityTime() {
        byte[] latestValidityTime_byte = new byte[8];
        if (!utils.readPages(8, 2, latestValidityTime_byte, 0)) {
            Log.e("getLatestValidityTime", "Reading time pages failed");
            return -1;
        }
        long latestValidityTime_long = byteArrayToLeLong(latestValidityTime_byte);
        return latestValidityTime_long;
    }

    private long getLatestExpiryTime(){
        byte[] latestExpiryTime_byte = new byte[8];
        if (!utils.readPages(10, 2, latestExpiryTime_byte, 0)) {
            Log.e("getLatestExpiryTime", "Reading time pages failed");
            return -1;
        }
        long latestExpiryTime_long = byteArrayToLeLong(latestExpiryTime_byte);
        return latestExpiryTime_long;
    }

    private boolean setExpiryDate(long timeToAdd){
        long expiryDate = System.currentTimeMillis() + timeToAdd*1000;
        if (!utils.writePages(createLengthOfModulOFour(leLongToByteArray(expiryDate)), 0,10 , 2)) {
            Log.e("setExpiryDate", "Writing a validity timer failed!");
            return false;
        }
        Log.d("setExpiryDate", "Succesfully set the expiry date!");
        return true;
    }

    private int getRemainingUses() {
        int rideCounter_int = getCurrentRidesCounter();
        int maxRideCounter_int = getNumberOfRides();
        if (rideCounter_int != -1 && maxRideCounter_int != -1) {
            remainingUses = maxRideCounter_int - rideCounter_int;
            return remainingUses;
        }
        return -1;
    }


    private boolean checkCredibility(int safeTicketMultiplier){
        if (getRemainingUses() >= safeTicketMultiplier*ticketsToAddPerTime){
            Log.e("checkCredibility","Too many valid tickets, might be counterfeit! (Remaining uses: " + getRemainingUses() + ")");
            return false;
        }
        long latestExpiryTime = getExpiryTime();
        long currentTime = System.currentTimeMillis();
        if ((latestExpiryTime - currentTime)/1000 >= timeToAdd*5){
            Log.e("checkCredibility","Expiry time too long, might be counterfeit!");
            return false;
        }
        return true;
    }

    // #######################################################################
    // ########################### Helper functions ##########################
    // #######################################################################
    public byte[] firstHalfOfByteArray(byte[] data) {
        return Arrays.copyOf(data, data.length / 2);
    }

    public byte[] secondHalfOfByteArray(byte[] data){
        return Arrays.copyOfRange(data, data.length/2, data.length);
    }

    private byte[] addTwoByteArrays(byte[] a1, byte[] a2) {
        byte[] byteArraysCombined = new byte[a1.length + a2.length];
        for (int i = 0; i < byteArraysCombined.length; i++) {
            if (i < a1.length) {
                byteArraysCombined[i] = a1[i];
            } else {
                byteArraysCombined[i] = a2[i - a1.length];
            }
        }
        return byteArraysCombined;
    }

    // source: https://stackoverflow.com/a/9855338
    private static String bytesToHex(byte[] bytes) {
        final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * This function is needed because we write per block of 4. So a byte array of length % 4 != 0 will yield an error
     * @param byteString
     * @return
     */
    private byte[] createLengthOfModulOFour(byte[] byteString) {
        if (byteString.length % 4 != 0) {
            int lengthToAdd = 4 - (byteString.length % 4);
            byte[] additionalByteString = new byte[lengthToAdd];
            byteString = addTwoByteArrays(byteString, additionalByteString);
        }
        return byteString;
    }

    /**
     * Source: https://stackoverflow.com/a/11419863
     * @param b
     * @return
     */
    public static int byteArrayToLeInt(byte[] b) {
        final ByteBuffer bb = ByteBuffer.wrap(b);
        bb.order(ByteOrder.LITTLE_ENDIAN);
        return bb.getInt();
    }

    public static long byteArrayToLeLong(byte[] b) {
        final ByteBuffer bb = ByteBuffer.wrap(b);
        bb.order(ByteOrder.LITTLE_ENDIAN);
        return bb.getLong();
    }

    /**
     * Source: https://stackoverflow.com/a/11419863
     * @param i
     * @return a byte array of length 4 (because int = 4 bytes)
     */
    public static byte[] leIntToByteArray(int i) {
        final ByteBuffer bb = ByteBuffer.allocate(Integer.SIZE / Byte.SIZE);
        bb.order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt(i);
        return bb.array();
    }

    public static byte[] leLongToByteArray(long i) {
        final ByteBuffer bb = ByteBuffer.allocate(Long.SIZE / Byte.SIZE);
        bb.order(ByteOrder.LITTLE_ENDIAN);
        bb.putLong(i);
        return bb.array();
    }
}
