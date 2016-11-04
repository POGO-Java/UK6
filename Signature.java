package com.pokegoapi.util;

import com.google.protobuf.ByteString;
import com.pokegoapi.api.PokemonGo;
import com.pokegoapi.api.device.LocationFixes;
import com.pokegoapi.exceptions.RemoteServerException;

import java.math.BigInteger;
import java.util.Random;

import POGOProtos.Networking.Envelopes.RequestEnvelopeOuterClass;
import POGOProtos.Networking.Envelopes.SignatureOuterClass;
import POGOProtos.Networking.Platform.PlatformRequestTypeOuterClass;
import POGOProtos.Networking.Platform.Requests.SendEncryptedSignatureRequestOuterClass;

public class Signature {

	/**
	 * Given a fully built request, set the signature correctly.
	 *
	 * @param api     the api
	 * @param builder the requestenvelop builder
	 * @param hashes the array with our hashes
	 */
	public static void setSignature(PokemonGo api, RequestEnvelopeOuterClass.RequestEnvelope.Builder builder, String[] hashes)
			throws RemoteServerException {

		if (builder.getAuthTicket() == null) {
			//System.out.println("Ticket == null");
			return;
		}

		long currentTime = api.currentTimeMillis();
		long timeSince = currentTime - api.getStartTime();

		Random random = new Random();

		SignatureOuterClass.Signature.Builder sigBuilder;
		try {
			sigBuilder = SignatureOuterClass.Signature.newBuilder()
					.setLocationHashByTokenSeed(new BigInteger(hashes[0]).intValue())
					.setLocationHash(new BigInteger(hashes[1]).intValue())
					.setEpochTimestampMs(currentTime)
					.setTimestampMsSinceStart(timeSince)
					.setDeviceInfo(api.getDeviceInfo())
					.setIosDeviceInfo(api.getActivitySignature(random))
					.addAllLocationUpdates(LocationFixes.getDefault(api, builder, currentTime, random))
					.setField22(ByteString.copyFrom(api.getSessionHash())) // random 16 bytes
					.setField25(-8408506833887075802L);
		} catch (NumberFormatException e) {
			return;
		}

		SignatureOuterClass.Signature.SensorUpdate sensorInfo = api.getSensorSignature(currentTime, random);
		if (sensorInfo != null) {
			sigBuilder.addSensorUpdates(sensorInfo);
		}

		for (int i=0;i<builder.getRequestsList().size();i++) {
			sigBuilder.addRequestHashes(new BigInteger(hashes[i+2]).longValue());
		}

		SignatureOuterClass.Signature signature = sigBuilder.build();
		byte[] sigbytes = signature.toByteArray();
		byte[] encrypted = Crypto43.encrypt(sigbytes, timeSince).toByteBuffer().array();

		ByteString signatureBytes = SendEncryptedSignatureRequestOuterClass.SendEncryptedSignatureRequest.newBuilder()
				.setEncryptedSignature(ByteString.copyFrom(encrypted)).build()
				.toByteString();

		RequestEnvelopeOuterClass.RequestEnvelope.PlatformRequest platformRequest = RequestEnvelopeOuterClass
				.RequestEnvelope.PlatformRequest.newBuilder()
				.setType(PlatformRequestTypeOuterClass.PlatformRequestType.SEND_ENCRYPTED_SIGNATURE)
				.setRequestMessage(signatureBytes)
				.build();
		builder.addPlatformRequests(platformRequest);
	}
}
