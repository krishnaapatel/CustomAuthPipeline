package com.alitaste.portal.security.auth;

import java.util.Properties;
import java.util.StringTokenizer;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.liferay.portal.kernel.json.JSONFactoryUtil;
import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.servlet.HttpHeaders;
import com.liferay.portal.kernel.util.Base64;
import com.liferay.portal.kernel.util.CharPool;
import com.liferay.portal.kernel.util.GetterUtil;
import com.liferay.portal.kernel.util.Http;
import com.liferay.portal.kernel.util.HttpUtil;
import com.liferay.portal.kernel.util.MapUtil;
import com.liferay.portal.kernel.util.PropsUtil;
import com.liferay.portal.kernel.util.StringUtil;
import com.liferay.portal.kernel.util.Validator;
import com.liferay.portal.model.Company;
import com.liferay.portal.model.CompanyConstants;
import com.liferay.portal.model.User;
import com.liferay.portal.security.auth.AccessControlContext;
import com.liferay.portal.security.auth.AuthException;
import com.liferay.portal.security.auth.AuthVerifier;
import com.liferay.portal.security.auth.AuthVerifierResult;
import com.liferay.portal.security.auth.Authenticator;
import com.liferay.portal.security.auth.AutoLoginException;
import com.liferay.portal.security.auth.BaseAutoLogin;
import com.liferay.portal.util.Portal;
import com.liferay.portal.util.PortalUtil;
import com.liferay.portal.model.User;
import com.liferay.portal.service.UserLocalServiceUtil;
import com.liferay.portal.kernel.json.JSONObject;
import com.liferay.portal.kernel.facebook.FacebookConnectUtil;
import com.liferay.portal.kernel.util.StringPool;

public class CustomJWTAuthVerifier extends BaseAutoLogin implements AuthVerifier{

	
	private static final String BEARER = "Bearer";

	@Override
	public String getAuthType() {
		return HttpServletRequest.BASIC_AUTH;
	}

	@Override
	public AuthVerifierResult verify(AccessControlContext accessControlContext, Properties properties)
		throws AuthException {

		try {
			AuthVerifierResult authVerifierResult = new AuthVerifierResult();

			String[] credentials = login(accessControlContext.getRequest(),accessControlContext.getResponse());

			if (credentials != null && Validator.isNotNull(credentials[0])) {
				authVerifierResult.setPassword(credentials[1]);
				authVerifierResult.setState(AuthVerifierResult.State.SUCCESS);
				authVerifierResult.setUserId(Long.valueOf(credentials[0]));
			}
			return authVerifierResult;
		}
		catch (AutoLoginException ale) {
			throw new AuthException(ale);
		}
	}

	@Override
	protected String[] doLogin(HttpServletRequest request, HttpServletResponse response)throws Exception {

		// Get the Authorization header, if one was supplied
		String authorization = request.getHeader("Authorization");
		if (authorization == null) {
			return null;
		}
		StringTokenizer st = new StringTokenizer(authorization);
		if (!st.hasMoreTokens()) {
			return null;
		}
		String basic = st.nextToken();
		if (!StringUtil.equalsIgnoreCase(basic, BEARER)) {
			return null;
		}

		String token = st.nextToken();
		String[] credentials = null;
		String[] tokenData = new TokenGenerator().decodeJWToken(token);
		try {
			if (Validator.isNotNull(tokenData) && tokenData != null) {
				credentials = new String[3];
				User user = UserLocalServiceUtil.getUser(Long.parseLong(tokenData[0]));
				if(Validator.isNotNull(tokenData[1]) && Validator.isNotNull(tokenData[2]) && Validator.isNotNull(user) && user.getUserId()> 0){
					Company company = PortalUtil.getCompany(request);
					String authType = company.getAuthType();
					
					if (authType.equals(CompanyConstants.AUTH_TYPE_EA)) {
						int authResult = UserLocalServiceUtil.authenticateByEmailAddress(company.getCompanyId(), tokenData[1], tokenData[2], null,null,null);
						if (authResult == Authenticator.SUCCESS) {
							credentials[0] = String.valueOf(user.getUserId());
							credentials[1] = tokenData[2];
							credentials[2] = Boolean.TRUE.toString();
						}
					}
					
				}
				if(Validator.isNotNull(tokenData[3]) && Long.parseLong(tokenData[3]) > 0 &&  user.getFacebookId() == Long.parseLong(tokenData[3])){
					credentials[0] = String.valueOf(user.getUserId());
					credentials[2] = Boolean.TRUE.toString();
				}
			}
		} catch (Exception e) {
			if (_log.isWarnEnabled()) {
				_log.warn(e, e);
			}
		}
		return credentials;
	}
	
	private static Log _log = LogFactoryUtil.getLog(
		CustomJWTAuthVerifier.class);
}
