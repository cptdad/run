/** A right-to-left swipe across the middle of the screen (W3C pointer — works
 *  on both UiAutomator2 and XCUITest). */
export async function swipeLeft(): Promise<void> {
    const size = await driver.getWindowSize()
    const y = Math.floor(size.height * 0.5)
    await driver.action('pointer')
        .move({ x: Math.floor(size.width * 0.85), y })
        .down()
        .pause(100)
        .move({ duration: 400, x: Math.floor(size.width * 0.15), y })
        .up()
        .perform()
}
