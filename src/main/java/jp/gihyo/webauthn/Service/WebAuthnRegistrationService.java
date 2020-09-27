package jp.gihyo.webauthn.Service;

import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;
import jp.gihyo.webauthn.entity.Credential;
import jp.gihyo.webauthn.entity.User;
import jp.gihyo.webauthn.repository.CredentialRepository;
import jp.gihyo.webauthn.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class WebAuthnRegistrationService {
	private final UserRepository userRepository;
	private final CredentialRepository credentialRepository;

	public WebAuthnRegistrationService(UserRepository userRepository, CredentialRepository credentialRepository) {
		this.userRepository = userRepository;
		this.credentialRepository = credentialRepository;
	}

	public PublicKeyCredentialCreationOptions creationOptions(User user) {
		var rpId = "localhost";
		var rpName = "Gihyo Relying Party";
		var rp = new PublicKeyCredentialRpEntity(rpId, rpName);

		var userId = user.getId();
		var userName = user.getEmail();
		var userDisplayName = user.getDisplayName();
		var userInfo = new PublicKeyCredentialUserEntity(
				userId,
				userName,
				userDisplayName
		);

		var challenge = new DefaultChallenge();

		var es256 = new PublicKeyCredentialParameters(
				PublicKeyCredentialType.PUBLIC_KEY,
				COSEAlgorithmIdentifier.ES256
		);

		var rs256 = new PublicKeyCredentialParameters(
				PublicKeyCredentialType.PUBLIC_KEY,
				COSEAlgorithmIdentifier.RS256
		);

		var pubKeyCredParams = List.of(es256, rs256);

		var timeout = 120000L;

		var credentials = credentialRepository.find(user.getId());
		var excludeCredentials = credentials.stream()
				.map(credential ->
						new PublicKeyCredentialDescriptor(
								PublicKeyCredentialType.PUBLIC_KEY,
								credential.getCredentialId(),
								Set.of()
						)).collect(Collectors.toList());

		var authenticatorAttachment = AuthenticatorAttachment.PLATFORM;
		var requireResidentKey = false;
		var userVerification = UserVerificationRequirement.REQUIRED;
		var authenticatorSelection = new AuthenticatorSelectionCriteria(
				authenticatorAttachment,
				requireResidentKey,
				userVerification
		);

		var attestation = AttestationConveyancePreference.DIRECT;
		var extensionMap = new HashMap<String, RegistrationExtensionClientInput>();
		var extensions = new AuthenticationExtensionsClientInputs<>(extensionMap);

		return new PublicKeyCredentialCreationOptions(
				rp,
				userInfo,
				challenge,
				pubKeyCredParams,
				timeout,
				excludeCredentials,
				authenticatorSelection,
				attestation,
				extensions
		);
	}

	public User findOrElseCreate(String email, String displayName) {
		return userRepository.find(email)
				.orElseGet(() -> createUser(email, displayName));
	}

	private User createUser(String email, String displayName) {
		var userId = new byte[32];
		new SecureRandom().nextBytes(userId);

		var user = new User();
		user.setId(userId);
		user.setEmail(email);
		user.setDisplayName(displayName);
		return user;
	}

	public void creationFinish(
			User user,
			Challenge challenge,
			byte[] clientDataJSON,
			byte[] attestationObject) {

		var origin = Origin.create("http://localhost:8080");
		var rpId = "localhost";
		var challengeBase64 = new DefaultChallenge(Base64.getEncoder().encode(challenge.getValue()));
		byte[] tokenBindingId = null;
		var serverProperty = new ServerProperty(
				origin,
				rpId,
				challengeBase64,
				tokenBindingId);

		var userVerificationRequired = true;

		var registrationContext = new WebAuthnRegistrationContext(
				clientDataJSON,
				attestationObject,
				serverProperty,
				userVerificationRequired);
		var validator = WebAuthnRegistrationContextValidator.createNonStrictRegistrationContextValidator();

		var response = validator.validate(registrationContext);

		var credentialId = response
				.getAttestationObject()
				.getAuthenticatorData()
				.getAttestedCredentialData()
				.getCredentialId();

		var authenticator = new AuthenticatorImpl(
				response.getAttestationObject().getAuthenticatorData().getAttestedCredentialData(),
				response.getAttestationObject().getAttestationStatement(),
				response.getAttestationObject().getAuthenticatorData().getSignCount(),
				Set.of(),
				response.getRegistrationExtensionsClientOutputs(),
				Map.of()
		);

		var signatureCounter = response
				.getAttestationObject()
				.getAuthenticatorData()
				.getSignCount();

		if (userRepository.find(user.getEmail()).isEmpty()) {
			userRepository.insert(user);
		}

		var authenticatorBin = new CborConverter().writeValueAsBytes(authenticator);

		var credential = new Credential();
		credential.setCredentialId(credentialId);
		credential.setUserId(user.getId());
		credential.setPublicKey(authenticatorBin);
		credential.setSignatureCounter(signatureCounter);
		credentialRepository.insert(credential);
	}
}
