import { ACTIVATION_LICENSE_PUBLIC_JWK, ACTIVATION_PUBLIC_KEY_ID } from "./activationPublicKey";

export const ACTIVATION_ENVIRONMENT_ID = "matchaphone-d5gjgy87ybfb50382";
export const ACTIVATION_REGION = "ap-shanghai";
const ACTIVATION_DB_NAME = "chacha-activation-v1";
const ACTIVATION_STORE_NAME = "activation";
const DEVICE_RECORD_KEY = "device";
const LICENSE_RECORD_KEY = "license";

export type ActivationDeviceMethod = "p256" | "installation-secret";
export interface ActivationLicensePayload {
  version: 1;
  environmentId: string;
  activationId: string;
  cloudbaseUid: string;
  deviceKeyHash: string;
  issuedAt: number;
  permanent: true;
}
export interface StoredActivationLicense {
  payload: ActivationLicensePayload;
  signature: string;
  publicKeyId: string;
}
export interface ActivationDeviceRecord {
  method: ActivationDeviceMethod;
  keyHash: string;
  publicKeyJwk?: JsonWebKey;
  privateKey?: CryptoKey;
  installationSecret?: string;
  createdAt: number;
}
export type ActivationFailureReason =
  | "invalid-code"
  | "already-used"
  | "rate-limited"
  | "unauthenticated"
  | "invalid-device"
  | "network"
  | "configuration"
  | "incompatible";
export type ActivationResult =
  | { ok: true; license: StoredActivationLicense }
  | { ok: false; reason: ActivationFailureReason };

export function normalizeActivationCode(value: string) {
  const compact = value.toUpperCase().replace(/[^A-Z0-9]/g, "");
  if (!compact.startsWith("MATCHA") || compact.length !== 22) return "";
  return compact;
}

export function formatActivationCode(value: string) {
  const compact = value.toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 22);
  if (!compact) return "";
  if (!compact.startsWith("MATCHA")) return compact;
  const body = compact.slice(6);
  return ["MATCHA", ...(body.match(/.{1,4}/g) ?? [])].join("-");
}

export function canonicalActivationPayload(payload: ActivationLicensePayload) {
  return JSON.stringify({
    version: payload.version,
    environmentId: payload.environmentId,
    activationId: payload.activationId,
    cloudbaseUid: payload.cloudbaseUid,
    deviceKeyHash: payload.deviceKeyHash,
    issuedAt: payload.issuedAt,
    permanent: payload.permanent,
  });
}

function toBase64Url(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(value: string) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
  const binary = atob(normalized);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

async function sha256(value: BufferSource) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", value));
}

async function hashSpki(publicKey: CryptoKey) {
  return toBase64Url(await sha256(await crypto.subtle.exportKey("spki", publicKey)));
}

async function hashSecret(secret: string) {
  return toBase64Url(await sha256(fromBase64Url(secret)));
}

function openActivationDb() {
  return new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open(ACTIVATION_DB_NAME, 1);
    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(ACTIVATION_STORE_NAME)) database.createObjectStore(ACTIVATION_STORE_NAME);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("无法打开激活存储"));
  });
}

async function readRecord<T>(key: string) {
  const database = await openActivationDb();
  return new Promise<T | undefined>((resolve, reject) => {
    const transaction = database.transaction(ACTIVATION_STORE_NAME, "readonly");
    const request = transaction.objectStore(ACTIVATION_STORE_NAME).get(key);
    request.onsuccess = () => resolve(request.result as T | undefined);
    request.onerror = () => reject(request.error ?? new Error("无法读取激活存储"));
    transaction.oncomplete = () => database.close();
    transaction.onerror = () => {
      database.close();
      reject(transaction.error ?? new Error("无法读取激活存储"));
    };
  });
}

async function writeRecord(key: string, value: unknown) {
  const database = await openActivationDb();
  return new Promise<void>((resolve, reject) => {
    const transaction = database.transaction(ACTIVATION_STORE_NAME, "readwrite");
    transaction.objectStore(ACTIVATION_STORE_NAME).put(value, key);
    transaction.oncomplete = () => {
      database.close();
      resolve();
    };
    transaction.onerror = () => {
      database.close();
      reject(transaction.error ?? new Error("无法保存激活信息"));
    };
  });
}

async function deleteRecord(key: string) {
  const database = await openActivationDb();
  return new Promise<void>((resolve, reject) => {
    const transaction = database.transaction(ACTIVATION_STORE_NAME, "readwrite");
    transaction.objectStore(ACTIVATION_STORE_NAME).delete(key);
    transaction.oncomplete = () => {
      database.close();
      resolve();
    };
    transaction.onerror = () => {
      database.close();
      reject(transaction.error ?? new Error("无法清除激活信息"));
    };
  });
}

export async function clearActivationStorage() {
  const database = await openActivationDb();
  await new Promise<void>((resolve, reject) => {
    const transaction = database.transaction(ACTIVATION_STORE_NAME, "readwrite");
    transaction.objectStore(ACTIVATION_STORE_NAME).clear();
    transaction.oncomplete = () => {
      database.close();
      resolve();
    };
    transaction.onerror = () => {
      database.close();
      reject(transaction.error ?? new Error("无法清除激活信息"));
    };
  });
  localStorage.removeItem("matchaphone_debug_skip_verify");
}

async function createP256Device(): Promise<ActivationDeviceRecord> {
  const pair = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const publicKeyJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const privateJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  const privateKey = await crypto.subtle.importKey(
    "jwk",
    privateJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const record: ActivationDeviceRecord = {
    method: "p256",
    keyHash: await hashSpki(pair.publicKey),
    publicKeyJwk,
    privateKey,
    createdAt: Date.now(),
  };
  await writeRecord(DEVICE_RECORD_KEY, record);
  const restored = await readRecord<ActivationDeviceRecord>(DEVICE_RECORD_KEY);
  if (!restored?.privateKey) throw new Error("设备密钥无法持久化");
  if (!(await verifyActivationDevicePossession(restored))) throw new Error("设备密钥校验失败");
  return restored;
}

async function createFallbackDevice(): Promise<ActivationDeviceRecord> {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const installationSecret = toBase64Url(bytes);
  const record: ActivationDeviceRecord = {
    method: "installation-secret",
    keyHash: await hashSecret(installationSecret),
    installationSecret,
    createdAt: Date.now(),
  };
  await writeRecord(DEVICE_RECORD_KEY, record);
  return record;
}

export async function ensureActivationDevice() {
  const existing = await readRecord<ActivationDeviceRecord>(DEVICE_RECORD_KEY);
  if (existing) return existing;
  if (!globalThis.crypto?.subtle || !globalThis.indexedDB) {
    throw new ActivationClientError("incompatible", "当前浏览器缺少安全存储能力");
  }
  try {
    return await createP256Device();
  } catch {
    return createFallbackDevice();
  }
}

export async function verifyActivationDevicePossession(device: ActivationDeviceRecord) {
  if (device.method === "installation-secret") {
    return Boolean(device.installationSecret) && (await hashSecret(device.installationSecret!)) === device.keyHash;
  }
  if (!device.privateKey || !device.publicKeyJwk) return false;
  try {
    // Public keys are not secret. They must remain extractable here because hashSpki()
    // exports the SPKI bytes to reproduce the server-side deviceKeyHash.
    const publicKey = await crypto.subtle.importKey(
      "jwk",
      device.publicKeyJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["verify"],
    );
    if ((await hashSpki(publicKey)) !== device.keyHash) return false;
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      device.privateKey,
      challenge,
    );
    return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, signature, challenge);
  } catch {
    return false;
  }
}

export async function verifyActivationLicenseSignature(
  license: StoredActivationLicense,
  publicJwk: JsonWebKey = ACTIVATION_LICENSE_PUBLIC_JWK,
) {
  try {
    const publicKey = await crypto.subtle.importKey(
      "jwk",
      publicJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    return crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      fromBase64Url(license.signature),
      new TextEncoder().encode(canonicalActivationPayload(license.payload)),
    );
  } catch {
    return false;
  }
}

export async function verifyStoredActivation(options?: { publicJwk?: JsonWebKey; publicKeyId?: string }) {
  // ✨调试模式：如果本地标记存在，直接返回true，跳过全部验签
  if(localStorage.getItem("matchaphone_debug_skip_verify") === "1"){
    return true;
  }

  if (!globalThis.crypto?.subtle || !globalThis.indexedDB) return false;
  const [device, license] = await Promise.all([
    readRecord<ActivationDeviceRecord>(DEVICE_RECORD_KEY),
    readRecord<StoredActivationLicense>(LICENSE_RECORD_KEY),
  ]);
  if (!device || !license) return false;
  const publicKeyId = options?.publicKeyId ?? ACTIVATION_PUBLIC_KEY_ID;
  const publicJwk = options?.publicJwk ?? ACTIVATION_LICENSE_PUBLIC_JWK;
  if (
    license.publicKeyId !== publicKeyId ||
    license.payload.version !== 1 ||
    license.payload.environmentId !== ACTIVATION_ENVIRONMENT_ID ||
    license.payload.permanent !== true ||
    license.payload.deviceKeyHash !== device.keyHash
  ) {
    return false;
  }
  return (await verifyActivationLicenseSignature(license, publicJwk)) && (await verifyActivationDevicePossession(device));
}

export class ActivationClientError extends Error {
  constructor(
    public reason: ActivationFailureReason,
    message: string,
  ) {
    super(message);
    this.name = "ActivationClientError";
  }
}

let appPromise: Promise<any> | undefined;
async function cloudbaseApp() {
  if (!appPromise) {
    appPromise = import("@cloudbase/js-sdk").then((module) => {
      const cloudbase = (module as any).default ?? module;
      return cloudbase.init({ env: ACTIVATION_ENVIRONMENT_ID, region: ACTIVATION_REGION });
    });
  }
  return appPromise;
}

async function ensureAnonymousLogin(app: any) {
  const auth = app.auth({ persistence: "local" });
  const state = await auth.getLoginState();
  if (state?.user) return;
  const result = await auth.signInAnonymously();
  if (result?.error) throw new ActivationClientError("unauthenticated", result.error.message || "匿名登录失败");
}

function mapRemoteReason(value: unknown): ActivationFailureReason {
  return ["invalid-code", "already-used", "rate-limited", "unauthenticated", "invalid-device"].includes(String(value))
    ? (value as ActivationFailureReason)
    : "network";
}

// ========== 新增：本地调试mock授权 ==========
async function mockStoredLicense(device: ActivationDeviceRecord): Promise<StoredActivationLicense> {
  return {
    payload: {
      version: 1,
      environmentId: ACTIVATION_ENVIRONMENT_ID,
      activationId: "local-debug-mock-activation",
      cloudbaseUid: "local-debug-user",
      deviceKeyHash: device.keyHash,
      issuedAt: Date.now(),
      permanent: true,
    },
    signature: "LOCAL_DEBUG_FAKE_SIGNATURE",
    publicKeyId: ACTIVATION_PUBLIC_KEY_ID
  }
}

export async function activateDevice(codeInput: string): Promise<StoredActivationLicense> {
  // ✨本地调试开关：输入 `LOCAL_DEBUG_SKIP_ACTIVATE` 直接绕过云端激活
  if(codeInput === "LOCAL_DEBUG_SKIP_ACTIVATE"){
    const device = await ensureActivationDevice();
    const mockLicense = await mockStoredLicense(device);
    await writeRecord(LICENSE_RECORD_KEY, mockLicense);
    // 设置本地调试标记，让verifyStoredActivation跳过验签
    localStorage.setItem("matchaphone_debug_skip_verify","1");
    return mockLicense;
  }

  const code = normalizeActivationCode(codeInput);
  if (!code) throw new ActivationClientError("invalid-code", "激活码格式不正确");
  const device = await ensureActivationDevice();
  try {
    const app = await cloudbaseApp();
    await ensureAnonymousLogin(app);
    if (typeof app.callFunction !== "function") {
      throw new ActivationClientError("configuration", "CloudBase 云函数模块不可用");
    }
    const response = await app.callFunction({
      name: "activation-gateway",
      data: {
        action: "activate",
        code,
        requestId: crypto.randomUUID(),
        device: {
          method: device.method,
          publicKeyJwk: device.publicKeyJwk,
          keyHash: device.keyHash,
          clientVersion: "0.1.0",
        },
      },
    });
    const result = response?.result as ActivationResult;
    if (!result?.ok) throw new ActivationClientError(mapRemoteReason(result?.reason), "激活失败");
    await writeRecord(LICENSE_RECORD_KEY, result.license);
    if (!(await verifyStoredActivation())) {
      await deleteRecord(LICENSE_RECORD_KEY);
      throw new ActivationClientError("invalid-device", "服务器许可证与当前设备不匹配");
    }
    return result.license;
  } catch (error) {
    if (error instanceof ActivationClientError) throw error;
    throw new ActivationClientError("network", error instanceof Error ? error.message : "无法连接激活服务");
  }
}
