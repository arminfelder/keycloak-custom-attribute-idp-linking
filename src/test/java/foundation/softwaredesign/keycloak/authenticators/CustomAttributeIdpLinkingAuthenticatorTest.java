package foundation.softwaredesign.keycloak.authenticators;

import foundation.softwaredesign.keycloak.authenticators.CustomAttributeIdpLinkingAuthenticator;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.events.Errors;
import org.keycloak.events.Event;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import org.keycloak.services.messages.Messages;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import twitter4j.User;

import javax.ws.rs.core.Response;
import java.util.*;
import java.util.stream.Stream;


public class CustomAttributeIdpLinkingAuthenticatorTest {

    @Before
    public void setup() {

    }

    @Test
    public void missingIdentityProviderAttribute(){
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        CustomAttributeIdpLinkingAuthenticator authenticator = new CustomAttributeIdpLinkingAuthenticator();
        AuthenticationFlowContext context = Mockito.mock(AuthenticationFlowContext.class);

        BrokeredIdentityContext brokerContext = new BrokeredIdentityContext("idp_attrib");

        UserModel result = authenticator.findMatchingUser(context,brokerContext,config);

        assertNull("failed to detect missing IDP attribute", result);

    }

    @Test
    public void emptyIdentityProviderAttribute(){
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        Map<String,String> configMap = new HashMap<String,String>();
        configMap.put(CustomAttributeIdpLinkingAuthenticatorFactory.CONFIG_IDP_ATTRIBUTE, "");
        config.setConfig(configMap);
        CustomAttributeIdpLinkingAuthenticator authenticator = new CustomAttributeIdpLinkingAuthenticator();
        AuthenticationFlowContext context = Mockito.mock(AuthenticationFlowContext.class);

        BrokeredIdentityContext brokerContext = new BrokeredIdentityContext("someId");

        UserModel result = authenticator.findMatchingUser(context,brokerContext,config);

        assertNull("failed to detect empty IDP attribute",result);

    }

    @Test
    public void brokerContextMissingIdentityProviderAttribute(){
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        Map<String,String> configMap = new HashMap<String,String>();
        configMap.put(CustomAttributeIdpLinkingAuthenticatorFactory.CONFIG_IDP_ATTRIBUTE, "idp_attrib");
        configMap.put(CustomAttributeIdpLinkingAuthenticatorFactory.CONFIG_LOOKUP_ATTRIBUTE, "idp_attrib");
        config.setConfig(configMap);
        CustomAttributeIdpLinkingAuthenticator authenticator = new CustomAttributeIdpLinkingAuthenticator();
        AuthenticationFlowContext context = Mockito.mock(AuthenticationFlowContext.class);

        BrokeredIdentityContext brokerContext = new BrokeredIdentityContext("someId");
        Map<String,Object> configMapBroker = new HashMap<String, Object>();
        brokerContext.setContextData(configMapBroker);

        UserModel result = authenticator.findMatchingUser(context,brokerContext,config);

        assertNull("failed to detect missing IDP attribute",result);

    }

    @Test
    public void brokerContextIdentityProviderSingleAttribute(){
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        Map<String,String> configMap = new HashMap<String,String>();
        configMap.put(CustomAttributeIdpLinkingAuthenticatorFactory.CONFIG_IDP_ATTRIBUTE, "idp_attrib");
        configMap.put(CustomAttributeIdpLinkingAuthenticatorFactory.CONFIG_LOOKUP_ATTRIBUTE, "idp_attrib");
        config.setConfig(configMap);
        CustomAttributeIdpLinkingAuthenticator authenticator = new CustomAttributeIdpLinkingAuthenticator();
        AuthenticationFlowContext context = Mockito.mock(AuthenticationFlowContext.class);

        BrokeredIdentityContext brokerContext = new BrokeredIdentityContext("someId");
        Map<String,Object> configMapBroker = new HashMap<String, Object>();
        configMapBroker.put("idp_attrib", "testid");
        brokerContext.setContextData(configMapBroker);

        KeycloakSession session = Mockito.mock(KeycloakSession.class);
        UserProvider userProvider = Mockito.mock(UserProvider.class);
        UserModel user = Mockito.mock(UserModel.class);
        RealmModel realModel = Mockito.mock(RealmModel.class);
        Stream<UserModel> userModelStream = (Stream<UserModel>) Mockito.mock(Stream.class);

        when(context.getSession()).thenReturn(session);
        when(session.users()).thenReturn(userProvider);
        when(userProvider.searchForUserByUserAttributeStream(any(), any(), any() )).thenReturn(userModelStream);
        when(userModelStream.findFirst()).thenReturn(Optional.ofNullable(user));

        UserModel result = authenticator.findMatchingUser(context,brokerContext,config);

        assertNotNull("failed to handle single IDP user attribute",result);

    }

    @Test
    public void brokerContextIdentityProviderMultipleAttributes(){
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        Map<String,String> configMap = new HashMap<String,String>();
        configMap.put(CustomAttributeIdpLinkingAuthenticatorFactory.CONFIG_IDP_ATTRIBUTE, "idp_attrib");
        configMap.put(CustomAttributeIdpLinkingAuthenticatorFactory.CONFIG_LOOKUP_ATTRIBUTE, "idp_attrib");
        config.setConfig(configMap);
        CustomAttributeIdpLinkingAuthenticator authenticator = new CustomAttributeIdpLinkingAuthenticator();
        AuthenticationFlowContext context = Mockito.mock(AuthenticationFlowContext.class);

        BrokeredIdentityContext brokerContext = new BrokeredIdentityContext("someId");
        Map<String,Object> configMapBroker = new HashMap<String, Object>();
        configMapBroker.put("idp_attrib", new ArrayList<String>(){
            {
                add("id1");
                add("id2");
                add("id3");
            }
        });
        brokerContext.setContextData(configMapBroker);

        KeycloakSession session = Mockito.mock(KeycloakSession.class);
        UserProvider userProvider = Mockito.mock(UserProvider.class);
        UserModel user = Mockito.mock(UserModel.class);
        RealmModel realModel = Mockito.mock(RealmModel.class);
        Stream<UserModel> userModelStream = (Stream<UserModel>) Mockito.mock(Stream.class);

        when(context.getSession()).thenReturn(session);
        when(session.users()).thenReturn(userProvider);
        when(userProvider.searchForUserByUserAttributeStream(any(), any(), any() )).thenReturn(userModelStream);
        when(userModelStream.findFirst()).thenReturn(Optional.ofNullable(user));

        UserModel result = authenticator.findMatchingUser(context,brokerContext,config);

        assertNotNull("failed to handle multiple IDP user attributes",result);

    }

    @Test
    public void validateAuthenticationConfigNotNull(){
        CustomAttributeIdpLinkingAuthenticator authenticator = new CustomAttributeIdpLinkingAuthenticator();
        AuthenticationFlowContext context = Mockito.mock(AuthenticationFlowContext.class);
        SerializedBrokeredIdentityContext serializedCtx = null;
        BrokeredIdentityContext brokerContext = null;
        AuthenticatorConfigModel authenticatorConfigModel = null;

        when(context.getAuthenticatorConfig()).thenReturn(authenticatorConfigModel);

        Exception exception = assertThrows(NullPointerException.class, () -> {
            authenticator.authenticateImpl(context,serializedCtx,brokerContext);
        });
    }

    @Test
    public void validateAuthenticationConfigMapNotNull(){
        CustomAttributeIdpLinkingAuthenticator authenticator = new CustomAttributeIdpLinkingAuthenticator();
        AuthenticationFlowContext context = Mockito.mock(AuthenticationFlowContext.class);
        SerializedBrokeredIdentityContext serializedCtx = null;
        BrokeredIdentityContext brokerContext = null;
        AuthenticatorConfigModel authenticatorConfigModel = new AuthenticatorConfigModel();
        authenticatorConfigModel.setConfig(null);

        when(context.getAuthenticatorConfig()).thenReturn(authenticatorConfigModel);

        Exception exception = assertThrows(NullPointerException.class, () -> {
            authenticator.authenticateImpl(context,serializedCtx,brokerContext);
        });
    }

    @Test
    public void failOnNoMatch(){
        CustomAttributeIdpLinkingAuthenticator authenticator = Mockito.mock(CustomAttributeIdpLinkingAuthenticator.class, CALLS_REAL_METHODS);
        AuthenticationFlowContext context = Mockito.mock(AuthenticationFlowContext.class);
        SerializedBrokeredIdentityContext serializedCtx = null;
        BrokeredIdentityContext brokerContext = new BrokeredIdentityContext("someId");
        Map<String,Object> configMapBroker = new HashMap<String, Object>();
        configMapBroker.put("idp_attrib", new ArrayList<String>(){
            {
                add("id1");
                add("id2");
                add("id3");
            }
        });
        brokerContext.setContextData(configMapBroker);

        AuthenticatorConfigModel authenticatorConfigModel = new AuthenticatorConfigModel();

        Map<String,String> configMap = new HashMap<String, String>();
        configMap.put(CustomAttributeIdpLinkingAuthenticatorFactory.CONFIG_IDP_ATTRIBUTE, "idp_attrib");
        configMap.put(CustomAttributeIdpLinkingAuthenticatorFactory.CONFIG_LOOKUP_ATTRIBUTE, "idp_attrib");
        configMap.put(CustomAttributeIdpLinkingAuthenticatorFactory.CONFIG_FAIL_ON_NO_MATCH_ATTRIBUTE, "true");
        authenticatorConfigModel.setConfig(configMap);

        KeycloakSession session = Mockito.mock(KeycloakSession.class);
        UserProvider userProvider = Mockito.mock(UserProvider.class);
        UserModel user = Mockito.mock(UserModel.class);
        Stream<UserModel> userModelStream = (Stream<UserModel>) Mockito.mock(Stream.class);
        EventBuilder eventBuilder = Mockito.mock(EventBuilder.class);
        LoginFormsProvider loginFormsProvider = Mockito.mock(LoginFormsProvider.class);

        when(context.getAuthenticatorConfig()).thenReturn(authenticatorConfigModel);
        when(context.getSession()).thenReturn(session);
        when(session.users()).thenReturn(userProvider);
        when(userProvider.searchForUserByUserAttributeStream(any(), any(), any() )).thenReturn(userModelStream);
        when(userModelStream.findFirst()).thenReturn(Optional.empty());
        when(context.getUser()).thenReturn(user);
        when(context.getEvent()).thenReturn(eventBuilder);
        when(eventBuilder.user(user)).thenReturn(eventBuilder);
        when(context.form()).thenReturn(loginFormsProvider);
        when(loginFormsProvider.setError(any(),any())).thenReturn(loginFormsProvider);
        doNothing().when(context).failureChallenge(any(),any());

        authenticator.authenticateImpl(context, serializedCtx, brokerContext);

        verify(context, times(0)).success();
    }

    @Test
    public void matchToExistingUser(){
        CustomAttributeIdpLinkingAuthenticator authenticator = Mockito.mock(CustomAttributeIdpLinkingAuthenticator.class, CALLS_REAL_METHODS);
        AuthenticationFlowContext context = Mockito.mock(AuthenticationFlowContext.class);
        SerializedBrokeredIdentityContext serializedCtx = null;
        BrokeredIdentityContext brokerContext = Mockito.mock(BrokeredIdentityContext.class,CALLS_REAL_METHODS);
        brokerContext.setId("someId");

        Map<String,Object> configMapBroker = new HashMap<String, Object>();
        configMapBroker.put("idp_attrib", new ArrayList<String>(){
            {
                add("id1");
                add("id2");
                add("id3");
            }
        });
        brokerContext.setContextData(configMapBroker);

        AuthenticatorConfigModel authenticatorConfigModel = new AuthenticatorConfigModel();

        Map<String,String> configMap = new HashMap<String, String>();
        configMap.put(CustomAttributeIdpLinkingAuthenticatorFactory.CONFIG_IDP_ATTRIBUTE, "idp_attrib");
        configMap.put(CustomAttributeIdpLinkingAuthenticatorFactory.CONFIG_LOOKUP_ATTRIBUTE, "idp_attrib");
        configMap.put(CustomAttributeIdpLinkingAuthenticatorFactory.CONFIG_FAIL_ON_NO_MATCH_ATTRIBUTE, "true");
        authenticatorConfigModel.setConfig(configMap);

        KeycloakSession session = Mockito.mock(KeycloakSession.class);
        UserProvider userProvider = Mockito.mock(UserProvider.class);
        UserModel user = Mockito.mock(UserModel.class);
        Stream<UserModel> userModelStream = (Stream<UserModel>) Mockito.mock(Stream.class);
        EventBuilder eventBuilder = Mockito.mock(EventBuilder.class);
        LoginFormsProvider loginFormsProvider = Mockito.mock(LoginFormsProvider.class);
        IdentityProviderModel identityProviderModel = Mockito.mock(IdentityProviderModel.class);

        when(context.getAuthenticatorConfig()).thenReturn(authenticatorConfigModel);
        when(context.getSession()).thenReturn(session);
        when(session.users()).thenReturn(userProvider);
        when(userProvider.searchForUserByUserAttributeStream(any(), any(), any() )).thenReturn(userModelStream);
        when(userModelStream.findFirst()).thenReturn(Optional.ofNullable(user));
        when(context.getUser()).thenReturn(user);
        when(context.getEvent()).thenReturn(eventBuilder);
        when(eventBuilder.user(user)).thenReturn(eventBuilder);
        when(context.form()).thenReturn(loginFormsProvider);
        when(loginFormsProvider.setError(any(),any())).thenReturn(loginFormsProvider);
        doNothing().when(context).failureChallenge(any(),any());
        when(user.getUsername()).thenReturn("User123");
        when(brokerContext.getIdpConfig()).thenReturn(identityProviderModel);
        when(identityProviderModel.getAlias()).thenReturn("idpAlias");
        when(brokerContext.getUsername()).thenReturn("User123");
        doNothing().when(context).setUser(any());

        authenticator.authenticateImpl(context, serializedCtx, brokerContext);

        verify(context, times(1)).success();
    }
}
