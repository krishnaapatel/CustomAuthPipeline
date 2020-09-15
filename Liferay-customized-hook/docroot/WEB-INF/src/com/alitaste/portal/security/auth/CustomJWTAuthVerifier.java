package com.alitaste.portal.security.auth;

import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.model.Company;
import com.liferay.portal.kernel.model.CompanyConstants;
import com.liferay.portal.kernel.model.User;
import com.liferay.portal.kernel.security.auth.AccessControlContext;
import com.liferay.portal.kernel.security.auth.AuthException;
import com.liferay.portal.kernel.security.auth.Authenticator;
import com.liferay.portal.kernel.security.auth.verifier.AuthVerifier;
import com.liferay.portal.kernel.security.auth.verifier.AuthVerifierResult;
import com.liferay.portal.kernel.security.auto.login.AutoLogin;
import com.liferay.portal.kernel.security.auto.login.AutoLoginException;
import com.liferay.portal.kernel.service.UserLocalServiceUtil;
import com.liferay.portal.kernel.util.PortalUtil;
import com.liferay.portal.kernel.util.StringUtil;
import com.liferay.portal.kernel.util.Validator;

import java.util.Properties;
import java.util.StringTokenizer;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.osgi.service.component.annotations.Component;

@Component(
	property = "auth.verifier.CustomJWTAuthVerifier.urls.includes=/api/jsonws/*",
	service = AuthVerifier.class
)
public class CustomJWTAuthVerifier implements AutoLogin, AuthVerifier{
	
	private static final String BEARER = "Bearer";
	
	
	@Override
	public String getAuthType() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public AuthVerifierResult verify(AccessControlContext accessControlContext, Properties properties)
			throws AuthException {
		// TODO Auto-generated method stub
		try {
			AuthVerifierResult authVerifierResult = new AuthVerifierResult();

			String[] credentials = login(accessControlContext.getRequest(),accessControlContext.getResponse());

			if (credentials != null && Validator.isNotNull(credentials[0])) {
				authVerifierResult.setPassword(credentials[1]);
				authVerifierResult.setState(AuthVerifierResult.State.SUCCESS);
				authVerifierResult.setUserId(Long.valueOf(credentials[0]));
				authVerifierResult.setPasswordBasedAuthentication(Boolean.TRUE);
			}
			return authVerifierResult;
		}
		catch (AutoLoginException ale) {
			throw new AuthException(ale);
		}
	}
	
	
	@Override
	public String[] handleException(HttpServletRequest request, HttpServletResponse response, Exception e)
			throws AutoLoginException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String[] login(HttpServletRequest request, HttpServletResponse response) throws AutoLoginException {
		// TODO Auto-generated method stub
		
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
