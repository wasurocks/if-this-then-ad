/**
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { Auth, AUTH_MODE, ServiceAccount } from '../../src/helpers/auth';

describe('Auth Helper', () => {
  const mockServiceAccount: ServiceAccount = {
    type: 'this.serviceAccount',
    project_id: 'test-project',
    private_key_id: 'key-id-123',
    private_key: '-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASC...',
    client_email: 'test-sa@test-project.iam.gserviceaccount.com',
    client_id: '123456789',
    auth_uri: 'https://accounts.google.com/o/oauth2/auth',
    token_uri: 'https://oauth2.googleapis.com/token',
    auth_provider_x509_cert_url: 'https://www.googleapis.com/oauth2/v1/certs',
    client_x509_cert_url: 'https://www.googleapis.com/robot/v1/metadata/x509/test-sa',
  };

  afterEach(() => {
    delete (global as Record<string, unknown>).PropertiesService;
    delete (global as Record<string, unknown>).ScriptApp;
    delete (global as Record<string, unknown>).OAuth2;
    jest.restoreAllMocks();
  });

  describe('constructor', () => {
    it('defaults to USER mode when no account and no PropertiesService', () => {
      const auth = new Auth();

      expect(auth.authMode).toBe(AUTH_MODE.USER);
      expect(auth.serviceAccount).toBeUndefined();
    });

    it('uses provided service account object directly', () => {
      const auth = new Auth(mockServiceAccount);

      expect(auth.authMode).toBe(AUTH_MODE.SERVICE_ACCOUNT);
      expect(auth.serviceAccount).toEqual(mockServiceAccount);
    });

    it('loads service account from Script Properties when account is not provided', () => {
      const getPropertyMock = jest.fn().mockReturnValue(JSON.stringify(mockServiceAccount));
      (global as Record<string, unknown>).PropertiesService = {
        getScriptProperties: () => ({
          getProperty: getPropertyMock,
        }),
      };

      const auth = new Auth();

      expect(getPropertyMock).toHaveBeenCalledWith('serviceAccount');
      expect(auth.authMode).toBe(AUTH_MODE.SERVICE_ACCOUNT);
      expect(auth.serviceAccount).toEqual(mockServiceAccount);
    });

    it('gracefully handles malformed JSON in Script Properties with console.warn', () => {
      const consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
      const getPropertyMock = jest.fn().mockReturnValue('{"invalid_json:');
      (global as Record<string, unknown>).PropertiesService = {
        getScriptProperties: () => ({
          getProperty: getPropertyMock,
        }),
      };

      const auth = new Auth();

      expect(getPropertyMock).toHaveBeenCalledWith('serviceAccount');
      expect(consoleWarnSpy).toHaveBeenCalledWith(
        'Failed to parse serviceAccount from Script Properties:',
        expect.any(Error)
      );
      expect(auth.authMode).toBe(AUTH_MODE.USER);
      expect(auth.serviceAccount).toBeUndefined();
    });

    it('defaults to USER mode when serviceAccount property is null or empty', () => {
      const getPropertyMock = jest.fn().mockReturnValue(null);
      (global as Record<string, unknown>).PropertiesService = {
        getScriptProperties: () => ({
          getProperty: getPropertyMock,
        }),
      };

      const auth = new Auth();

      expect(getPropertyMock).toHaveBeenCalledWith('serviceAccount');
      expect(auth.authMode).toBe(AUTH_MODE.USER);
      expect(auth.serviceAccount).toBeUndefined();
    });

    it('prefers explicit account over Script Properties', () => {
      const getPropertyMock = jest.fn();
      (global as Record<string, unknown>).PropertiesService = {
        getScriptProperties: () => ({
          getProperty: getPropertyMock,
        }),
      };

      const customAccount = { ...mockServiceAccount, project_id: 'explicit-project' };
      const auth = new Auth(customAccount);

      expect(getPropertyMock).not.toHaveBeenCalled();
      expect(auth.authMode).toBe(AUTH_MODE.SERVICE_ACCOUNT);
      expect(auth.serviceAccount).toEqual(customAccount);
    });
  });

  describe('getAuthToken', () => {
    it('returns token from ScriptApp in USER mode', () => {
      (global as Record<string, unknown>).ScriptApp = {
        getOAuthToken: jest.fn().mockReturnValue('mock-user-token'),
      };

      const auth = new Auth();
      const token = auth.getAuthToken();

      expect(token).toBe('mock-user-token');
      expect(((global as Record<string, unknown>).ScriptApp as { getOAuthToken: jest.Mock }).getOAuthToken).toHaveBeenCalled();
    });

    it('throws error in SERVICE_ACCOUNT mode if service account is invalid', () => {
      const invalidAccount = { client_email: 'sa@test.com' };
      const auth = new Auth(invalidAccount);

      expect(() => auth.getAuthToken()).toThrow('No or invalid service account provided');
    });

    it('configures OAuth2 service and returns access token without domain-wide delegation', () => {
      const mockOAuthService = {
        setTokenUrl: jest.fn().mockReturnThis(),
        setPrivateKey: jest.fn().mockReturnThis(),
        setIssuer: jest.fn().mockReturnThis(),
        setSubject: jest.fn().mockReturnThis(),
        setPropertyStore: jest.fn().mockReturnThis(),
        setParam: jest.fn().mockReturnThis(),
        setScope: jest.fn().mockReturnThis(),
        reset: jest.fn().mockReturnThis(),
        getAccessToken: jest.fn().mockReturnValue('mock-sa-token'),
      };

      (global as Record<string, unknown>).OAuth2 = {
        createService: jest.fn().mockReturnValue(mockOAuthService),
      };
      (global as Record<string, unknown>).PropertiesService = {
        getScriptProperties: jest.fn().mockReturnValue('mock-store'),
      };

      const auth = new Auth(mockServiceAccount);
      const token = auth.getAuthToken();

      expect(token).toBe('mock-sa-token');
      expect(((global as Record<string, unknown>).OAuth2 as { createService: jest.Mock }).createService).toHaveBeenCalledWith(
        'Service Account'
      );
      expect(mockOAuthService.setTokenUrl).toHaveBeenCalledWith('https://accounts.google.com/o/oauth2/token');
      expect(mockOAuthService.setPrivateKey).toHaveBeenCalledWith(mockServiceAccount.private_key);
      expect(mockOAuthService.setIssuer).toHaveBeenCalledWith(mockServiceAccount.client_email);
      expect(mockOAuthService.setSubject).not.toHaveBeenCalled();
      expect(mockOAuthService.setScope).toHaveBeenCalledWith('https://www.googleapis.com/auth/display-video');
      expect(mockOAuthService.reset).toHaveBeenCalled();
      expect(mockOAuthService.getAccessToken).toHaveBeenCalled();
    });

    it('calls setSubject when user_email is present in service account', () => {
      const mockOAuthService = {
        setTokenUrl: jest.fn().mockReturnThis(),
        setPrivateKey: jest.fn().mockReturnThis(),
        setIssuer: jest.fn().mockReturnThis(),
        setSubject: jest.fn().mockReturnThis(),
        setPropertyStore: jest.fn().mockReturnThis(),
        setParam: jest.fn().mockReturnThis(),
        setScope: jest.fn().mockReturnThis(),
        reset: jest.fn().mockReturnThis(),
        getAccessToken: jest.fn().mockReturnValue('mock-delegated-token'),
      };

      (global as Record<string, unknown>).OAuth2 = {
        createService: jest.fn().mockReturnValue(mockOAuthService),
      };
      (global as Record<string, unknown>).PropertiesService = {
        getScriptProperties: jest.fn().mockReturnValue('mock-store'),
      };

      const delegatedAccount: ServiceAccount = {
        ...mockServiceAccount,
        user_email: 'delegated-user@example.com',
      };

      const auth = new Auth(delegatedAccount);
      const token = auth.getAuthToken();

      expect(token).toBe('mock-delegated-token');
      expect(mockOAuthService.setSubject).toHaveBeenCalledWith('delegated-user@example.com');
    });
  });
});
