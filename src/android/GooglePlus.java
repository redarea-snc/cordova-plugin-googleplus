package nl.xservices.plugins;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.accounts.AccountManagerFuture;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.util.Log;

import com.google.android.gms.auth.api.signin.GoogleSignIn;
import com.google.android.gms.auth.api.signin.GoogleSignInClient;
import com.google.android.gms.auth.api.signin.GoogleSignInOptions;
import com.google.android.gms.auth.api.signin.GoogleSignInAccount;
import com.google.android.gms.common.api.ApiException;
import com.google.android.gms.common.api.Scope;

import com.google.android.gms.tasks.OnCanceledListener;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.OnFailureListener;
import com.google.android.gms.tasks.Task;
import org.apache.cordova.*;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

import android.content.pm.Signature;

/**
 * Originally written by Eddy Verbruggen (http://github.com/EddyVerbruggen/cordova-plugin-googleplus)
 * Forked/Duplicated and Modified by PointSource, LLC, 2016.
 */
public class GooglePlus extends CordovaPlugin {

    public static final String ACTION_IS_AVAILABLE = "isAvailable";
    public static final String ACTION_LOGIN = "login";
    public static final String ACTION_TRY_SILENT_LOGIN = "trySilentLogin";
    public static final String ACTION_LOGOUT = "logout";
    public static final String ACTION_DISCONNECT = "disconnect";
    public static final String ACTION_GET_SIGNING_CERTIFICATE_FINGERPRINT = "getSigningCertificateFingerprint";

    private final static String FIELD_ACCESS_TOKEN      = "accessToken";
    private final static String FIELD_TOKEN_EXPIRES     = "expires";
    private final static String FIELD_TOKEN_EXPIRES_IN  = "expires_in";
    private final static String VERIFY_TOKEN_URL        = "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=";

    //String options/config object names passed in to login and trySilentLogin
    public static final String ARGUMENT_WEB_CLIENT_ID = "webClientId";
    public static final String ARGUMENT_SCOPES = "scopes";
    public static final String ARGUMENT_OFFLINE_KEY = "offline";
    public static final String ARGUMENT_HOSTED_DOMAIN = "hostedDomain";

    public static final String TAG = "GooglePlugin";
    public static final int RC_GOOGLESIGNIN = 77552; // Request Code to identify our plugin's activities
    public static final int KAssumeStaleTokenSec = 60;

    // Wraps our service connection to Google Play services and provides access to the users sign in state and Google APIs
    private GoogleSignInClient mGoogleSignInClient;
    private CallbackContext savedCallbackContext;

    // Scopes needed to be granted
    private List<Scope> requestedScopes;
    // Last web client id used to build GoogleSignInClient
    private String mWebClientId;
    // Last hosted domain used to build GoogleSignInClient
    private String mHostedDomain;
    // Last offline access configuration used to build GoogleSignInClient
    private boolean mOfflineAccess;

    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
    }

    @Override
    public boolean execute(String action, CordovaArgs args, CallbackContext callbackContext) throws JSONException {
        this.savedCallbackContext = callbackContext;

        if (ACTION_IS_AVAILABLE.equals(action)) {
            final boolean avail = true;
            savedCallbackContext.success("" + avail);
        } else if (ACTION_LOGIN.equals(action)) {
            // Tries to Log the user in
            Log.i(TAG, "Trying to Log in!");
            checkGoogleSignInClient(args.optJSONObject(0), action);

        } else if (ACTION_TRY_SILENT_LOGIN.equals(action)) {
            Log.i(TAG, "Trying to do silent login!");
            checkGoogleSignInClient(args.optJSONObject(0), action);

        } else if (ACTION_LOGOUT.equals(action)) {
            Log.i(TAG, "Trying to logout!");
            signOut();

        } else if (ACTION_DISCONNECT.equals(action)) {
            Log.i(TAG, "Trying to disconnect the user");
            disconnect();

        } else if (ACTION_GET_SIGNING_CERTIFICATE_FINGERPRINT.equals(action)) {
            getSigningCertificateFingerprint();

        } else {
            Log.i(TAG, "This action doesn't exist");
            return false;

        }
        return true;
    }

    private void buildGoogleSignInClient(String actionExecuted){
        if(mGoogleSignInClient == null){
            Log.i(TAG, "Building Google options");

            //2019-02-01 - According to this piece of documentation: https://developers.google.com/identity/sign-in/android/people ,
            // requestProfile is already included in GoogleSignInOptions.DEFAULT_SIGN_IN
            GoogleSignInOptions.Builder gsoBuilder = new GoogleSignInOptions.Builder(GoogleSignInOptions.DEFAULT_SIGN_IN).requestEmail();
            if(requestedScopes.size() > 0){
                for(Scope scope: requestedScopes){
                    gsoBuilder.requestScopes(scope);
                }
            }

            if(mWebClientId != null){
                if(mOfflineAccess){
                    gsoBuilder.requestServerAuthCode(mWebClientId, true);
                }
                else{
                    gsoBuilder.requestIdToken(mWebClientId);
                }
            }
            GoogleSignInOptions gso = gsoBuilder.build();

            mGoogleSignInClient = GoogleSignIn.getClient(cordova.getActivity(), gso);
        }


        if(ACTION_TRY_SILENT_LOGIN.equals(actionExecuted)){
            Task<GoogleSignInAccount> task = mGoogleSignInClient.silentSignIn();
            handleSignInResult(task, ACTION_TRY_SILENT_LOGIN);
        }
        else{
            // Force user login interface
            Intent signInIntent = mGoogleSignInClient.getSignInIntent();
            cordova.startActivityForResult(this, signInIntent, RC_GOOGLESIGNIN);
        }
    }

    /**
     * Rut Bastoni - 2019-02-01 - new Google Sign in flow
     * @see https://developers.google.com/identity/sign-in/android/start-integrating
     * @see https://android-developers.googleblog.com/2017/11/moving-past-googleapiclient_21.html for migrating away from GoogleApiClient
     * @param clientOptions
     */
    private synchronized void checkGoogleSignInClient(JSONObject clientOptions, String actionExecuted) {
        List<Scope> previousRequestedScopes = requestedScopes;
        requestedScopes = new ArrayList<>();

        String webClientId = null;
        // Try to get hosted domain
        String hostedDomain = null;
        boolean offlineAccess = false;
        // Check if this call has more scopes than previous requests
        boolean hasExtraScopes = false;
        if(clientOptions != null){
            // Set requested scopes - can be different among different login execution, if the application needs to request
            // incremental scopes
            String scopes = clientOptions.optString(ARGUMENT_SCOPES, null);

            if (scopes != null && !scopes.isEmpty()) {
                // We have a string of scopes passed in. Split by space and request
                for (String scope : scopes.split(" ")) {
                    if(!scope.isEmpty()){
                        requestedScopes.add(new Scope(scope));

                        if(previousRequestedScopes != null && !previousRequestedScopes.contains(scope)){
                            hasExtraScopes = true;
                        }
                    }
                }
            }

            // Try to get web client id
            webClientId = clientOptions.optString(ARGUMENT_WEB_CLIENT_ID, null);
            if(webClientId != null && webClientId.isEmpty()){
                webClientId = null;
            }
            else{
                // Can have offlineAccess only with clientId
                offlineAccess = clientOptions.optBoolean(ARGUMENT_OFFLINE_KEY, false);
            }


            // Try to get hosted domain, if any
            hostedDomain = clientOptions.optString(ARGUMENT_HOSTED_DOMAIN, null);
            if(hostedDomain != null && hostedDomain.isEmpty()){
                hostedDomain = null;
            }
        }

        String previousWebClientId = mWebClientId;
        String previousHostedDomain = mHostedDomain;
        boolean previousOfflineAccess = mOfflineAccess;

        mWebClientId = webClientId;
        mHostedDomain = hostedDomain;
        mOfflineAccess = offlineAccess;

        // If webClientId or hostedDomain changed, should sign out and get a new client
        if (
                mGoogleSignInClient != null
                        && (
                        hasExtraScopes ||
                                (mWebClientId != null && !mWebClientId.equals(previousWebClientId))
                                || (
                                (mHostedDomain != null && !mHostedDomain.equals(previousHostedDomain))
                                        || (mHostedDomain == null && previousHostedDomain != null)
                        )
                                || (!previousOfflineAccess && mOfflineAccess)
                )
        ){

            mGoogleSignInClient
                    .signOut()
                    .addOnCompleteListener(cordova.getActivity(), new OnCompleteListener<Void>() {
                        @Override
                        public void onComplete(@NonNull Task<Void> task) {
                            mGoogleSignInClient = null;
                            buildGoogleSignInClient(actionExecuted);
                        }
                    })
                    .addOnFailureListener(cordova.getActivity(), new OnFailureListener() {
                        @Override
                        public void onFailure(@NonNull Exception e) {
                            Log.e(TAG, e.getMessage());
                            e.printStackTrace();

                            savedCallbackContext.error(e.getMessage());
                        }
                    })
                    .addOnCanceledListener(cordova.getActivity(), new OnCanceledListener() {
                        @Override
                        public void onCanceled() {
                            String msg = "Building new GoogleSignInClient failed - was canceled";
                            Log.e(TAG, msg);
                            savedCallbackContext.error(msg);
                        }
                    });
            return;
        }

        buildGoogleSignInClient(actionExecuted);
    }

    /**
     * Function for handling the sign in result
     * Handles the result of the authentication workflow.
     *
     * If the sign in was successful, we build and return an object containing the users email, id, displayname,
     * id token, and (optionally) the server authcode.
     *
     * If sign in was not successful, for some reason, we return the status code to web app to be handled.
     * Some important Status Codes:
     *      SIGN_IN_CANCELLED = 12501 -> cancelled by the user, flow exited, oauth consent denied
     *      SIGN_IN_FAILED = 12500 -> sign in attempt didn't succeed with the current account
     *      SIGN_IN_REQUIRED = 4 -> Sign in is needed to access API but the user is not signed in
     *      INTERNAL_ERROR = 8
     *      NETWORK_ERROR = 7
     *
     * @param completedTask
     * @param action
     */
    private void handleSignInResult(Task<GoogleSignInAccount> completedTask, String action) {
        if(completedTask.isSuccessful()){
            // There's immediate result available.
            GoogleSignInAccount signInAccount = completedTask.getResult();
            loginSuccess(signInAccount);
        }
        else{
            // There's no immediate result ready, waits for the async callback.
            completedTask
                    .addOnCompleteListener(cordova.getActivity(), new OnCompleteListener<GoogleSignInAccount>() {
                        @Override
                        public void onComplete(@NonNull Task<GoogleSignInAccount> task) {
                            try{
                                GoogleSignInAccount signInAccount = task.getResult(ApiException.class);
                                loginSuccess(signInAccount);
                            }catch (ApiException apiException){
                                // For a list of available status codes: https://developers.google.com/android/reference/com/google/android/gms/common/api/CommonStatusCodes
                                savedCallbackContext.error(apiException.getStatusCode());
                            }

                        }
                    })
                    .addOnCanceledListener(cordova.getActivity(), new OnCanceledListener() {
                        @Override
                        public void onCanceled() {
                            String msg = "GoogleSignInClient " + action + " failed - was canceled";
                            Log.e(TAG, msg);
                            savedCallbackContext.error(msg);
                        }
                    });
        }
    }

    private void loginSuccess(GoogleSignInAccount googleSignInAccount){
        JSONObject result = new JSONObject();
        try{
            //--04/02/2019 - Rut Bastoni - It's not recommended to perform backend server authentication here, it should
            // send idToken/serverAuthCode and let the server do it for you like explained in here: https://developers.google.com/identity/sign-in/android/backend-auth#using-a-google-api-client-library
            // Anyway, it's possible to do it with Google API Client Library, if needed
//            JSONObject accessTokenBundle = getAuthToken(
//                    cordova.getActivity(), googleSignInAccount.getAccount(), true
//            );
            result.put("email", googleSignInAccount.getEmail());
            result.put("idToken", googleSignInAccount.getIdToken());
            result.put("serverAuthCode", googleSignInAccount.getServerAuthCode());
            result.put("userId", googleSignInAccount.getId());
            result.put("displayName", googleSignInAccount.getDisplayName());
            result.put("familyName", googleSignInAccount.getFamilyName());
            result.put("givenName", googleSignInAccount.getGivenName());
            result.put("imageUrl", googleSignInAccount.getPhotoUrl());
            savedCallbackContext.success(result);
        }catch (JSONException e){
            savedCallbackContext.error("Trouble obtaining result, error: " + e.getMessage());
        }

    }

    /**
     * Signs the user out from the client
     */
    private void signOut() {
        if (this.mGoogleSignInClient == null) {
            savedCallbackContext.error("Please use login or trySilentLogin before logging out");
            return;
        }

        mGoogleSignInClient
                .signOut()
                .addOnCompleteListener(cordova.getActivity(), new OnCompleteListener<Void>() {
                    @Override
                    public void onComplete(@NonNull Task<Void> task) {
                        try{
                            task.getResult(ApiException.class);
                            savedCallbackContext.success("Logged user out");
                        }catch (ApiException apiException){
                            // For a list of available status codes: https://developers.google.com/android/reference/com/google/android/gms/common/api/CommonStatusCodes
                            savedCallbackContext.error(apiException.getStatusCode());
                        }

                    }
                });
    }

    /**
     * Disconnects the user and revokes access
     */
    private void disconnect() {
        if (this.mGoogleSignInClient == null) {
            savedCallbackContext.error("Please use login or trySilentLogin before disconnecting");
            return;
        }

        mGoogleSignInClient
                .revokeAccess()
                .addOnCompleteListener(cordova.getActivity(), new OnCompleteListener<Void>() {
                    @Override
                    public void onComplete(@NonNull Task<Void> task) {
                        try{
                            task.getResult(ApiException.class);
                            savedCallbackContext.success("Disconnected user");
                        }catch (ApiException apiException){
                            // For a list of available status codes: https://developers.google.com/android/reference/com/google/android/gms/common/api/CommonStatusCodes
                            savedCallbackContext.error(apiException.getStatusCode());
                        }
                    }
                });
    }

    /**
     * Listens for and responds to an activity result. If the activity result request code matches our own,
     * we know that the sign in Intent that we started has completed.
     *
     * The result is retrieved and send to the handleSignInResult function.
     *
     * @param requestCode The request code originally supplied to startActivityForResult(),
     * @param resultCode The integer result code returned by the child activity through its setResult().
     * @param intent Information returned by the child activity
     */
    @Override
    public void onActivityResult(int requestCode, final int resultCode, final Intent intent) {
        super.onActivityResult(requestCode, resultCode, intent);

        Log.i(TAG, "In onActivityResult");

        if (requestCode == RC_GOOGLESIGNIN) {
            Log.i(TAG, "One of our activities finished up");
            Task<GoogleSignInAccount> task = GoogleSignIn.getSignedInAccountFromIntent(intent);
            handleSignInResult(task, ACTION_LOGIN);
        }
        else {
            Log.i(TAG, "This wasn't one of our activities");
        }
    }

    private void getSigningCertificateFingerprint() {
        String packageName = webView.getContext().getPackageName();
        int flags = PackageManager.GET_SIGNATURES;
        PackageManager pm = webView.getContext().getPackageManager();
        try {
            PackageInfo packageInfo = pm.getPackageInfo(packageName, flags);
            Signature[] signatures = packageInfo.signatures;
            byte[] cert = signatures[0].toByteArray();

            String strResult = "";
            MessageDigest md;
            md = MessageDigest.getInstance("SHA1");
            md.update(cert);
            for (byte b : md.digest()) {
                String strAppend = Integer.toString(b & 0xff, 16);
                if (strAppend.length() == 1) {
                    strResult += "0";
                }
                strResult += strAppend;
                strResult += ":";
            }
            // strip the last ':'
            strResult = strResult.substring(0, strResult.length()-1);
            strResult = strResult.toUpperCase();
            this.savedCallbackContext.success(strResult);

        } catch (Exception e) {
            e.printStackTrace();
            savedCallbackContext.error(e.getMessage());
        }
    }

    private JSONObject getAuthToken(Activity activity, Account account, boolean retry) throws Exception {
        AccountManager manager = AccountManager.get(activity);
        AccountManagerFuture<Bundle> future = manager.getAuthToken(account, "oauth2:profile email", null, activity, null, null);
        Bundle bundle = future.getResult();
        String authToken = bundle.getString(AccountManager.KEY_AUTHTOKEN);
        try {
            return verifyToken(authToken);
        } catch (IOException e) {
            if (retry) {
                manager.invalidateAuthToken("com.google", authToken);
                return getAuthToken(activity, account, false);
            } else {
                throw e;
            }
        }
    }

    private JSONObject verifyToken(String authToken) throws IOException, JSONException {
        URL url = new URL(VERIFY_TOKEN_URL+authToken);
        HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
        urlConnection.setInstanceFollowRedirects(true);
        String stringResponse = fromStream(
                new BufferedInputStream(urlConnection.getInputStream())
        );
        /* expecting:
        {
            "issued_to": "608941808256-43vtfndets79kf5hac8ieujto8837660.apps.googleusercontent.com",
            "audience": "608941808256-43vtfndets79kf5hac8ieujto8837660.apps.googleusercontent.com",
            "user_id": "107046534809469736555",
            "scope": "https://www.googleapis.com/auth/userinfo.profile",
            "expires_in": 3595,
            "access_type": "offline"
        }*/

        Log.d("AuthenticatedBackend", "token: " + authToken + ", verification: " + stringResponse);
        JSONObject jsonResponse = new JSONObject(
                stringResponse
        );
        int expires_in = jsonResponse.getInt(FIELD_TOKEN_EXPIRES_IN);
        if (expires_in < KAssumeStaleTokenSec) {
            throw new IOException("Auth token soon expiring.");
        }
        jsonResponse.put(FIELD_ACCESS_TOKEN, authToken);
        jsonResponse.put(FIELD_TOKEN_EXPIRES, expires_in + (System.currentTimeMillis()/1000));
        return jsonResponse;
    }

    public static String fromStream(InputStream is) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(is));
        StringBuilder sb = new StringBuilder();
        String line = null;
        while ((line = reader.readLine()) != null) {
            sb.append(line).append("\n");
        }
        reader.close();
        return sb.toString();
    }
}
