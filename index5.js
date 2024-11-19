const axios = require("axios");
const readline = require("readline");
const crypto = require("crypto");

// AES GCM Decryption Class
class TBSAlgoEncryptDecrypt {
  static ALGORITHM = "aes-256-gcm";
  static GCM_IV_LENGTH = 12; // Length of the initialization vector (IV)
  static GCM_TAG_LENGTH = 16; // Length of the authentication tag

  // AES-GCM Decryption
  static gcmDecrypt(encryptedData, secretKey) {
    // Decode the base64 URL-encoded encrypted data
    const encryptedBuffer = Buffer.from(encryptedData, "base64");

    // Extract the IV (first 12 bytes)
    const iv = encryptedBuffer.slice(0, this.GCM_IV_LENGTH);
    console.log("IV:", iv.toString("base64")); // Debugging IV

    // Extract the ciphertext (remaining bytes except the last 16 for the tag)
    const ciphertext = encryptedBuffer.slice(
      this.GCM_IV_LENGTH,
      encryptedBuffer.length - this.GCM_TAG_LENGTH
    );
    console.log("Ciphertext:", ciphertext.toString("base64")); // Debugging ciphertext

    // Extract the authentication tag (last 16 bytes)
    const authTag = encryptedBuffer.slice(
      encryptedBuffer.length - this.GCM_TAG_LENGTH
    );
    console.log("Authentication Tag:", authTag.toString("base64")); // Debugging authTag

    // Create the decipher instance
    const decipher = crypto.createDecipheriv(
      this.ALGORITHM,
      Buffer.from(secretKey, "base64"),
      iv
    );

    // Set the authentication tag
    decipher.setAuthTag(authTag);

    try {
      // Decrypt the data
      let decrypted = decipher.update(ciphertext, null, "utf8");
      decrypted += decipher.final("utf8");
      return decrypted;
    } catch (error) {
      console.error("Decryption failed:", error.message);
      throw error;
    }
  }
}

// URLs for each request
const urlLogin =
  "https://uat-api-algo.tradebulls.in/ms-algo-trading-authservice/login";
const urlSendOtp =
  "https://uat-api-algo.tradebulls.in/ms-algo-trading-authservice/sendOtp";
const urlLogin2faTotp =
  "https://uat-api-algo.tradebulls.in/ms-algo-trading-authservice/login2faTotp";
const urlCustomerProfile =
  "https://uat-api-algo.tradebulls.in/ms-trading-customer-profile/loggedinuser/profiledetails";

// Headers for each request
const headers = {
  "request-info":
    '{"rit":"123","cver":"1.0v","ch":"WEB","info":{},"reqts":"12345678","payload":[]}',
  "x-api-key": "E6J9HA1BA31EJK90IK12KL80BBRRN590",
  "Content-Type": "application/json",
};

// Secret key (already base64-encoded)
const secretKey = "id+qipZHEPff/jNJPlyjKObYKcM+JWqzYFGGGzJh+mc=";

// Variables to store tokens
let loginToken = null;
let otpToken = null;
let accessToken = null;

// Read user input using readline
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

// Step 1: Login Request
const login = async () => {
  try {
    console.log("Starting Login...");
    const response = await axios.post(
      urlLogin,
      {
        username: "A0012",
        password: "Jan@2024",
        clientId: "tbsenterpriseweb",
        appId: "1",
        vendorName: "MintMaster",
        state: "Mint",
      },
      { headers }
    );

    if (response.status === 200) {
      console.log("Login Response:", response.data);

      loginToken = response.data?.data?.success?.logintoken;
      if (loginToken) {
        console.log("Login Token:", loginToken);
        await sendOtp();
      } else {
        console.error("Logintoken not found in login response.");
      }
    } else {
      console.error("Login failed with status:", response.status);
    }
  } catch (error) {
    console.error("An error occurred during login:", error.message);
  }
};

// Step 2: Send OTP Request
const sendOtp = async () => {
  try {
    console.log("Sending OTP...");
    const response = await axios.post(
      urlSendOtp,
      {
        payload: [{ logintoken: loginToken, product: "OTP2FA" }],
      },
      { headers }
    );

    if (response.status === 200) {
      console.log("Send OTP Response:", response.data);

      otpToken = response.data?.data?.success?.otpToken;
      if (otpToken) {
        console.log("OTP Token:", otpToken);

        const otpCode = 123456; // Replace with dynamic user input
        console.log("Enter OTP Code:", otpCode);
        await verifyTotp(otpCode);
      } else {
        console.error("OTP Token not found in response.");
      }
    } else {
      console.error("Send OTP failed with status:", response.status);
    }
  } catch (error) {
    console.error("An error occurred while sending OTP:", error.message);
  }
};

// Step 3: TOTP Verification and Decryption
const verifyTotp = async (otpCode) => {
  try {
    console.log("Verifying TOTP...");
    const response = await axios.post(
      urlLogin2faTotp,
      {
        payload: [{ logintoken: loginToken, otp: otpCode, authFlag: "0" }],
      },
      { headers }
    );

    if (response.status === 200) {
      console.log("TOTP Verification Response:", response.data);

      // Encrypted access token
      const encryptedAccessToken = response.data?.data?.success?.access_token;

      if (encryptedAccessToken) {
        console.log("Encrypted Access Token:", encryptedAccessToken);

        // Decrypt the access token
        const decryptedAccessToken = TBSAlgoEncryptDecrypt.gcmDecrypt(
          encryptedAccessToken,
          secretKey // Use the predefined secret key
        );

        console.log("Decrypted Access Token:", decryptedAccessToken);

        // Use the decrypted token for the next step (fetch customer profile)
        await getCustomerProfile(decryptedAccessToken);
      } else {
        console.error("Access token not found in TOTP response.");
      }
    } else {
      console.error("Failed TOTP verification. Status Code:", response.status);
    }
  } catch (error) {
    console.error("An error occurred during TOTP verification:", error.message);
  }
};

// Step 4: Get Customer Profile (Using Decrypted Token)
const getCustomerProfile = async (decryptedAccessToken) => {
  try {
    console.log("Fetching Customer Profile...");

    // Set the Authorization header with the decrypted access token
    headers.Authorization = `Bearer ${decryptedAccessToken}`;

    const response = await axios.get(urlCustomerProfile, { headers });

    if (response.status === 200) {
      console.log("Customer Profile Response:", response.data);

      const customerProfile = response.data?.data?.success;
      if (customerProfile) {
        console.log("Customer Details:", customerProfile);
      } else {
        console.error("Customer profile details not found.");
      }
    } else {
      console.error(
        `Failed to fetch customer profile. Status Code: ${response.status}`
      );
    }
  } catch (error) {
    console.error(
      "An error occurred while fetching customer profile:",
      error.message
    );
  }
};

// Start the workflow
login();
