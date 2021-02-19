//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use super::*;
use async_trait::async_trait;

fn sender_key_name_to_jobject<'a>(
    env: &JNIEnv<'a>,
    sender_key_name: &SenderKeyName,
) -> Result<JObject<'a>, SignalJniError> {
    let sender_key_name_class =
        env.find_class("org/whispersystems/libsignal/groups/SenderKeyName")?;
    let sender_key_name_ctor_args = [
        JObject::from(env.new_string(sender_key_name.group_id()?)?).into(),
        JObject::from(env.new_string(sender_key_name.sender_name()?)?).into(),
        JValue::from(sender_key_name.sender_device_id().convert_into(env)?),
    ];

    let sender_key_name_ctor_sig = "(Ljava/lang/String;Ljava/lang/String;I)V";
    let sender_key_name_jobject = env.new_object(
        sender_key_name_class,
        sender_key_name_ctor_sig,
        &sender_key_name_ctor_args,
    )?;
    Ok(sender_key_name_jobject)
}

pub type JavaSenderKeyStore<'a> = JObject<'a>;

pub struct JniSenderKeyStore<'a> {
    env: &'a JNIEnv<'a>,
    store: JObject<'a>,
}

impl<'a> JniSenderKeyStore<'a> {
    pub(crate) fn new(env: &'a JNIEnv, store: JObject<'a>) -> Result<Self, SignalJniError> {
        check_jobject_type(
            &env,
            store,
            "org/whispersystems/libsignal/groups/state/SenderKeyStore",
        )?;
        Ok(Self { env, store })
    }
}

impl<'a> JniSenderKeyStore<'a> {
    fn do_store_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        record: &SenderKeyRecord,
    ) -> Result<(), SignalJniError> {
        let sender_key_name_jobject = sender_key_name_to_jobject(self.env, sender_key_name)?;
        let sender_key_record_jobject = jobject_from_native_handle(
            self.env,
            "org/whispersystems/libsignal/groups/state/SenderKeyRecord",
            box_object::<SenderKeyRecord>(Ok(record.clone()))?,
        )?;

        let callback_args = [
            sender_key_name_jobject.into(),
            sender_key_record_jobject.into(),
        ];
        let callback_sig = "(Lorg/whispersystems/libsignal/groups/SenderKeyName;Lorg/whispersystems/libsignal/groups/state/SenderKeyRecord;)V";
        call_method_checked(
            self.env,
            self.store,
            "storeSenderKey",
            callback_sig,
            &callback_args[..],
        )?;

        Ok(())
    }

    fn do_load_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
    ) -> Result<Option<SenderKeyRecord>, SignalJniError> {
        let sender_key_name_jobject = sender_key_name_to_jobject(self.env, sender_key_name)?;
        let callback_args = [sender_key_name_jobject.into()];
        let callback_sig = "(Lorg/whispersystems/libsignal/groups/SenderKeyName;)Lorg/whispersystems/libsignal/groups/state/SenderKeyRecord;";

        let skr = get_object_with_native_handle::<SenderKeyRecord>(
            self.env,
            self.store,
            &callback_args,
            callback_sig,
            "loadSenderKey",
        )?;

        Ok(skr)
    }
}

#[async_trait(?Send)]
impl<'a> SenderKeyStore for JniSenderKeyStore<'a> {
    async fn store_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        record: &SenderKeyRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        Ok(self.do_store_sender_key(sender_key_name, record)?)
    }

    async fn load_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        _ctx: Context,
    ) -> Result<Option<SenderKeyRecord>, SignalProtocolError> {
        Ok(self.do_load_sender_key(sender_key_name)?)
    }
}
