package com.vg.run.ui.theme

import androidx.compose.ui.graphics.Color

// ---------------------------------------------------------------------------
// Rún colour palette — dark theme only.
//
// A single fixed palette with no light variant.
// ---------------------------------------------------------------------------

val RunBlack      = Color(0xFF0D0D0D)   // Primary background — near-black
val RunSurface    = Color(0xFF1A1A1A)   // Elevated surfaces (keypad buttons, cards)
val RunSurfaceAlt = Color(0xFF252525)   // Pressed / hovered state, input fields
val RunWhite      = Color(0xFFF0F0F0)   // Primary text
val RunGrey       = Color(0xFF666666)   // Secondary text / empty dots
val RunAccent     = Color(0xFFD4D4D4)   // Filled dots / subtle highlights
val RunError      = Color(0xFFCF6679)   // Error flash (shake animation)

// ---------------------------------------------------------------------------
// Rune dialog chrome — the shared modal look (artist mock 2026-07-20): a dark
// stone card with a worn light border, parchment uppercase text, hairline
// dividers, and an amber/ash split action row. Keep in sync with the iOS
// RuneDialog.swift tokens.
// ---------------------------------------------------------------------------
val RuneCardFill     = Color(0xFF161515)   // dialog card fill
val RuneBorderBright = Color(0xFF73706A)   // worn border, top edge
val RuneBorderDim    = Color(0xFF45423E)   // worn border, bottom edge
val RuneParchment    = Color(0xFFF0E7D5)   // dialog body text
val RuneGold         = Color(0xFFD3A878)   // primary action
val RuneAsh          = Color(0xFFA0A0A0)   // secondary action
val RuneHairline     = Color(0xFF413F3C)   // dialog hairline dividers
// Destructive action. A warm ember red, NOT RunError (#CF6679) — that rose is
// a Material-derived tone and reads cold against the parchment/gold chrome.
val RuneDanger       = Color(0xFFD4463A)

// Message bubble for sent messages — very subtle elevation over black.
val RunBubbleSent     = Color(0xFF2A2A2A)
// Message bubble for received messages — slightly lighter to differentiate.
val RunBubbleReceived = Color(0xFF1E1E1E)

// ---------------------------------------------------------------------------
// Avatar colours — deterministic palette for contact initials circles.
// Muted tones that sit well against the dark background without being garish.
// The colour is selected by hashing the contactId, so the same contact always
// gets the same colour across sessions. No real identity info is leaked.
// ---------------------------------------------------------------------------
val AvatarColors = listOf(
    Color(0xFF5C6BC0),   // indigo
    Color(0xFF26A69A),   // teal
    Color(0xFFEF5350),   // red
    Color(0xFFAB47BC),   // purple
    Color(0xFF42A5F5),   // blue
    Color(0xFFFF7043),   // deep orange
    Color(0xFF66BB6A),   // green
    Color(0xFFEC407A),   // pink
    Color(0xFF8D6E63),   // brown
    Color(0xFF78909C)    // blue-grey
)
