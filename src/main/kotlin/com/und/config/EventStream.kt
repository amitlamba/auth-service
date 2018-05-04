package com.und.config

import org.springframework.cloud.stream.annotation.Input
import org.springframework.cloud.stream.annotation.Output
import org.springframework.messaging.MessageChannel
import org.springframework.messaging.SubscribableChannel


interface EventStream {

//    @Input("emailEvent")
//    fun emailEventSend(): SubscribableChannel

//    @Input("campaignTrigger")
//    fun campaignTriggerSend(): SubscribableChannel

    @Output("clientEmail")
    fun clientEmailSend(): MessageChannel

//    @Input("EmailUpdate")
//    fun emailUpdateEvent(): SubscribableChannel
//
//    @Input("clickTrackEvent")
//    fun clickTrackEvent(): SubscribableChannel


//    @Output("emailEvent")
//    fun outputEmailEvent(): MessageChannel
}