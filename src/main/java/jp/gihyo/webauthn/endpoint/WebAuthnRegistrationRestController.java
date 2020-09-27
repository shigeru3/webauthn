package jp.gihyo.webauthn.endpoint;

import com.webauthn4j.data.PublicKeyCredentialCreationOptions;
import com.webauthn4j.data.client.challenge.Challenge;
import jp.gihyo.webauthn.Service.WebAuthnRegistrationService;
import jp.gihyo.webauthn.entity.User;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
public class WebAuthnRegistrationRestController {
	private final WebAuthnRegistrationService webAuthnService;

	public WebAuthnRegistrationRestController(WebAuthnRegistrationService webAuthnService) {
		this.webAuthnService = webAuthnService;
	}

	private static class AttestationOptionParam {
		public String email;
		public String displayName;
	}

	@PostMapping(value = "/attestation/options")
	public PublicKeyCredentialCreationOptions postAttestationOption(
			@RequestBody AttestationOptionParam params,
			HttpServletRequest httpRequest) {
		var user = webAuthnService.findOrElseCreate(params.email, params.displayName);
		var options = webAuthnService.creationOptions(user);

		var session = httpRequest.getSession();
		session.setAttribute("attestationChallenge", options.getChallenge());
		session.setAttribute("attestationUser", user);
		return options;
	}

	private static class AttestationResultParam {
		public byte[] clientDataJSON;
		public byte[] attestationObject;
	}

	@PostMapping(value = "/attestation/result")
	public void postAttestationOptions(
			@RequestBody AttestationResultParam params,
			HttpServletRequest httpRequest) {
		var httpSession = httpRequest.getSession();
		var challenge = (Challenge) httpSession.getAttribute("attestationChallenge");
		var user = (User) httpSession.getAttribute("attestationUser");

		httpSession.removeAttribute("attestationChallenge");
		httpSession.removeAttribute("attestationUser");

		webAuthnService.creationFinish(
				user,
				challenge,
				params.clientDataJSON,
				params.attestationObject
		);
	}
}
