package com.abdelama.sms.test;

import static org.junit.Assert.*;

import org.junit.Ignore;
import org.junit.Test;
import org.smpp.Data;

public class TestSomething {
	
	@Test
	public void CheckResult(){
		System.out.println(Data.SM_UDH_GSM + " " + (byte) 64);
		assertEquals(Data.SM_UDH_GSM, (byte) 64);
	}

}
